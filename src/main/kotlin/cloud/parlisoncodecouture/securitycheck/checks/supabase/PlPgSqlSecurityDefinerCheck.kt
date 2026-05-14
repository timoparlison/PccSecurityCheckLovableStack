package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.Finding
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.core.resultOf
import cloud.parlisoncodecouture.securitycheck.core.skipped
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import kotlin.io.path.extension
import kotlin.io.path.isRegularFile
import kotlin.io.path.readText
import kotlin.io.path.walk

@CheckId(name = "plpgsql-secdef-audit")
class PlPgSqlSecurityDefinerCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    @Suppress("UNUSED_PARAMETER") httpClient: cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient =
        cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "PL/pgSQL SECURITY DEFINER Audit"
    override val description =
        "Scannt lokale Migrations (*.sql) nach CREATE FUNCTION-Blöcken. Für SECURITY DEFINER-Functions " +
            "werden geprüft: explicit SET search_path, expliziter auth.uid()/role-Check, parametrisierte " +
            "EXECUTE-Calls (USING) statt format()-Konkatenation."
    override val category = "Supabase / DB Functions"

    // Dollar-Quote-Tag (Gruppe 3) ist beliebig (\w*), Schluss-Tag matcht via Backreference \3.
    // Damit erfasst die Regex sowohl $$...$$ als auch $func$...$func$, $body$...$body$ usw.
    private val funcRegex = Regex(
        "CREATE\\s+(?:OR\\s+REPLACE\\s+)?FUNCTION\\s+([\\w.]+)\\s*\\([^)]*\\)([\\s\\S]*?)\\\$(\\w*)\\\$([\\s\\S]*?)\\\$\\3\\\$",
        RegexOption.IGNORE_CASE,
    )

    @OptIn(kotlin.io.path.ExperimentalPathApi::class)
    override fun run(): CheckResult {
        val start = Instant.now()
        val migrations = config.migrationsPath
            ?: return skipped("migrations.path ist nicht gesetzt — Check übersprungen.", start)

        if (!Files.isDirectory(migrations)) {
            return skipped("migrations.path zeigt nicht auf ein Verzeichnis: $migrations", start)
        }

        val sqlFiles = migrations.walk()
            .filter { it.isRegularFile() && it.extension.equals("sql", ignoreCase = true) }
            .toList()

        if (sqlFiles.isEmpty()) {
            return skipped("Keine *.sql-Dateien unter $migrations gefunden.", start)
        }

        val findings = mutableListOf<Finding>()
        var totalFunctions = 0
        var secdefFunctions = 0

        for (file in sqlFiles) {
            val content = runCatching { file.readText() }.getOrNull() ?: continue
            for (match in funcRegex.findAll(content)) {
                totalFunctions++
                val functionName = match.groupValues[1]
                val signatureAndOptions = match.groupValues[2]
                // groupValues[3] = Dollar-Tag (z. B. "", "func", "body") — nicht genutzt
                val body = match.groupValues[4]
                val fullBlock = match.value

                val isSecdef = Regex("""\bSECURITY\s+DEFINER\b""", RegexOption.IGNORE_CASE).containsMatchIn(signatureAndOptions)
                if (!isSecdef) continue
                secdefFunctions++

                val location = relativeLocation(migrations, file, content, match.range.first)
                val findingsForFn = mutableListOf<Finding>()

                val hasSearchPath = Regex("""\bSET\s+search_path\b""", RegexOption.IGNORE_CASE)
                    .containsMatchIn(signatureAndOptions)
                if (!hasSearchPath) {
                    findingsForFn += Finding(
                        CheckStatus.RED,
                        "SECDEF '$functionName' ohne SET search_path",
                        "$location — ohne explicit 'SET search_path = …' kann ein Angreifer mit CREATE-Rechten in einem " +
                            "anderen Schema (z. B. pg_temp) Objekte unter denselben Namen anlegen und so beliebigen Code " +
                            "im Owner-Kontext ausführen (search_path-Hijack).",
                    )
                }

                val callsAuthOrRoleCheck = Regex(
                    """auth\.uid\(\)|auth\.jwt\(\)|current_setting\(\s*'request\.jwt|has_role\(""",
                    RegexOption.IGNORE_CASE,
                ).containsMatchIn(body)
                if (!callsAuthOrRoleCheck) {
                    findingsForFn += Finding(
                        CheckStatus.YELLOW,
                        "SECDEF '$functionName' ohne erkennbaren auth/role-Check",
                        "$location — Function bypasst RLS (DEFINER). Ohne expliziten auth.uid()-/role-Check " +
                            "kann jeder authentifizierte User die Function mit beliebigen Parametern aufrufen.",
                    )
                }

                val unsafeExecute = Regex(
                    """\bEXECUTE\s+format\s*\([^)]*%[ILs][^)]*\)(?![^;]*USING\b)""",
                    setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
                ).containsMatchIn(body)
                if (unsafeExecute) {
                    findingsForFn += Finding(
                        CheckStatus.RED,
                        "SECDEF '$functionName' verwendet format()-EXECUTE ohne USING",
                        "$location — Dynamisches SQL via EXECUTE format(…) ohne nachfolgendes USING bedeutet, dass " +
                            "Werte über String-Konkatenation eingebaut werden. Klassischer SQL-Injection-Vektor.",
                    )
                }

                val executeWithLiteral = Regex(
                    """\bEXECUTE\s+['"]?[^;]*\|\|""",
                    RegexOption.IGNORE_CASE,
                ).containsMatchIn(body)
                if (executeWithLiteral) {
                    findingsForFn += Finding(
                        CheckStatus.RED,
                        "SECDEF '$functionName' baut EXECUTE per || zusammen",
                        "$location — String-Konkatenation in EXECUTE ist SQL-Injection-anfällig. Stattdessen EXECUTE … USING \$1 nutzen.",
                    )
                }

                if (findingsForFn.isEmpty()) {
                    findings += Finding(
                        CheckStatus.GREEN,
                        "SECDEF '$functionName' wirkt strukturell sauber",
                        "$location — search_path gesetzt, auth-Check vorhanden, keine offensichtliche Injection.",
                    )
                } else {
                    findings += findingsForFn
                }
            }
        }

        if (totalFunctions == 0) {
            return resultOf(
                findings = listOf(Finding(CheckStatus.GREEN, "Keine CREATE FUNCTION-Blöcke gefunden", "${sqlFiles.size} SQL-Datei(en) gescannt.")),
                summary = "0 Functions in ${sqlFiles.size} Migrations.",
                start = start,
            )
        }
        if (secdefFunctions == 0) {
            return resultOf(
                findings = listOf(Finding(CheckStatus.GREEN, "Keine SECURITY DEFINER-Functions", "$totalFunctions Function(s) ohne DEFINER — kein Audit-Bedarf.")),
                summary = "0 von $totalFunctions Function(s) sind SECDEF.",
                start = start,
            )
        }

        val summary = "$secdefFunctions SECDEF von $totalFunctions Functions in ${sqlFiles.size} Migrations geprüft."
        return resultOf(findings, summary, start)
    }

    private fun relativeLocation(root: Path, file: Path, content: String, charOffset: Int): String {
        val rel = root.relativize(file).toString()
        val line = content.substring(0, charOffset.coerceAtMost(content.length)).count { it == '\n' } + 1
        return "$rel:$line"
    }
}

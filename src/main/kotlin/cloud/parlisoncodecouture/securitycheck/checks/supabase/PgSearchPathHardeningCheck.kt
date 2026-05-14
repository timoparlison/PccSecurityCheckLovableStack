package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.Finding
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.core.resultOf
import cloud.parlisoncodecouture.securitycheck.core.skipped
import cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import kotlin.io.path.extension
import kotlin.io.path.isRegularFile
import kotlin.io.path.readText
import kotlin.io.path.walk

@CheckId(name = "pg-search-path-hardening")
class PgSearchPathHardeningCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    @Suppress("UNUSED_PARAMETER") httpClient: SupabaseHttpClient = SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "Postgres search_path-Hardening"
    override val description =
        "Statische Analyse der Migrations: scannt alle CREATE FUNCTION (auch SECURITY INVOKER), " +
            "ALTER ROLE … SET search_path und ALTER DATABASE … SET search_path. INVOKER-Functions ohne " +
            "expliziten SET search_path sind anfällig für search_path-Hijack, wenn sie aus einem höher " +
            "privilegierten Kontext aufgerufen werden (Trigger, RLS-Policy, View einer SECDEF-Function). " +
            "DEFINER-Functions werden vom plpgsql-secdef-audit separat berichtet — hier nur INVOKER + " +
            "Rollen-/DB-weite Konfiguration. Mutable search_paths an Rollen oder DB sind ein systemisches " +
            "Risiko (BSI APP.4.6 / OWASP A03)."
    override val category = "Supabase / DB Functions"

    // Gleiches Pattern wie plpgsql-secdef-audit: unterstützt beliebige Dollar-Quote-Tags
    // ($$...$$ ebenso wie $func$...$func$) via Backreference auf Gruppe 3.
    private val funcRegex = Regex(
        "CREATE\\s+(?:OR\\s+REPLACE\\s+)?FUNCTION\\s+([\\w.]+)\\s*\\([^)]*\\)([\\s\\S]*?)\\\$(\\w*)\\\$([\\s\\S]*?)\\\$\\3\\\$",
        RegexOption.IGNORE_CASE,
    )
    private val alterRoleRegex = Regex(
        """ALTER\s+ROLE\s+(\w+)\s+SET\s+search_path\s*(?:=|TO)\s*([^;]+);""",
        RegexOption.IGNORE_CASE,
    )
    private val alterDbRegex = Regex(
        """ALTER\s+DATABASE\s+(\w+)\s+SET\s+search_path\s*(?:=|TO)\s*([^;]+);""",
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
        var invokerWithoutSearchPath = 0

        for (file in sqlFiles) {
            val content = runCatching { file.readText() }.getOrNull() ?: continue

            for (match in funcRegex.findAll(content)) {
                totalFunctions++
                val functionName = match.groupValues[1]
                val signatureAndOptions = match.groupValues[2]

                val isSecdef = Regex("""\bSECURITY\s+DEFINER\b""", RegexOption.IGNORE_CASE)
                    .containsMatchIn(signatureAndOptions)
                if (isSecdef) continue // wird vom plpgsql-secdef-audit abgedeckt

                val hasSearchPath = Regex("""\bSET\s+search_path\b""", RegexOption.IGNORE_CASE)
                    .containsMatchIn(signatureAndOptions)
                if (!hasSearchPath) {
                    invokerWithoutSearchPath++
                    val location = relativeLocation(migrations, file, content, match.range.first)
                    findings += Finding(
                        CheckStatus.YELLOW,
                        "INVOKER-Function '$functionName' ohne SET search_path",
                        "$location — Function läuft mit Rechten des Aufrufers, aber ohne expliziten " +
                            "search_path. Wird sie aus einem Trigger, einer RLS-Policy oder einer " +
                            "SECDEF-Function aufgerufen, kann ein Angreifer durch Anlegen gleichnamiger " +
                            "Objekte in einem höher gelisteten Schema (z. B. pg_temp) ausgeführten Code " +
                            "umlenken. Empfehlung: 'SET search_path = public, pg_temp' im Function-Header.",
                    )
                }
            }

            for (match in alterRoleRegex.findAll(content)) {
                val role = match.groupValues[1]
                val pathSetting = match.groupValues[2].trim()
                val location = relativeLocation(migrations, file, content, match.range.first)
                val mutable = pathSetting.contains("\$user", ignoreCase = true) ||
                    pathSetting.contains("\"\$user\"", ignoreCase = true)
                if (mutable) {
                    findings += Finding(
                        CheckStatus.YELLOW,
                        "ALTER ROLE '$role' setzt mutablen search_path",
                        "$location — search_path enthält '\$user'. Damit ist der search_path vom aktuellen " +
                            "User abhängig; Functions ohne expliziten SET search_path werden in einem " +
                            "nicht-deterministischen Schema-Kontext ausgeführt. Lieber statisch setzen " +
                            "(z. B. 'public, pg_temp').",
                        evidence = "search_path = $pathSetting",
                    )
                }
            }

            for (match in alterDbRegex.findAll(content)) {
                val db = match.groupValues[1]
                val pathSetting = match.groupValues[2].trim()
                val location = relativeLocation(migrations, file, content, match.range.first)
                findings += Finding(
                    CheckStatus.YELLOW,
                    "ALTER DATABASE '$db' setzt search_path",
                    "$location — datenbankweite search_path-Änderung ist systemisch und betrifft alle " +
                        "Sessions. Prüfen, dass kein '\$user'-Anteil enthalten ist und Schemas " +
                        "(insbesondere pg_temp) bewusst sortiert sind.",
                    evidence = "search_path = $pathSetting",
                )
            }
        }

        if (totalFunctions == 0) {
            return resultOf(
                findings = listOf(
                    Finding(
                        CheckStatus.GREEN,
                        "Keine CREATE FUNCTION gefunden",
                        "${sqlFiles.size} SQL-Datei(en) gescannt.",
                    ),
                ),
                summary = "0 Functions.",
                start = start,
            )
        }

        if (findings.isEmpty()) {
            findings += Finding(
                CheckStatus.GREEN,
                "Alle INVOKER-Functions haben SET search_path",
                "$totalFunctions Function(s) in ${sqlFiles.size} Migrations geprüft, keine Rollen-/DB-weiten " +
                    "Auffälligkeiten.",
            )
        }

        val summary = "$invokerWithoutSearchPath INVOKER-Function(s) ohne SET search_path (von $totalFunctions)."
        return resultOf(findings, summary, start)
    }

    private fun relativeLocation(root: Path, file: Path, content: String, charOffset: Int): String {
        val rel = root.relativize(file).toString()
        val line = content.substring(0, charOffset.coerceAtMost(content.length)).count { it == '\n' } + 1
        return "$rel:$line"
    }
}

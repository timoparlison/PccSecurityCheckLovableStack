package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.CodeLocation
import cloud.parlisoncodecouture.securitycheck.core.Finding
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.core.resultOf
import cloud.parlisoncodecouture.securitycheck.core.skipped
import cloud.parlisoncodecouture.securitycheck.db.CatalogAccess
import cloud.parlisoncodecouture.securitycheck.db.CatalogQuery
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
    private val catalog: CatalogAccess,
    @Suppress("UNUSED_PARAMETER") httpClient: cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient =
        cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient(config),
    // Runtime-Overlay: liefert pro SECDEF-Function (Key lowercased — sowohl 'schema.name' als auch 'name')
    // true, wenn pg_proc.proconfig einen 'search_path=…'-Eintrag enthält. null = Lookup nicht möglich
    // (z. B. keine Katalogquelle) → Befunde bleiben rein statisch. Tests können die Lookup-Funktion injizieren.
    private val runtimeHardenedLookup: () -> Map<String, Boolean>? = { loadRuntimeHardenedSecdef(catalog) },
) : SecurityCheck {
    override val name = "PL/pgSQL SECURITY DEFINER Audit"
    override val description =
        "Scannt lokale Migrations (*.sql) nach CREATE FUNCTION-Blöcken. Für SECURITY DEFINER-Functions " +
            "werden geprüft: explicit SET search_path, expliziter auth.uid()/role-Check, parametrisierte " +
            "EXECUTE-Calls (USING) statt format()-Konkatenation. Wenn eine Katalogquelle verfügbar ist, wird das " +
            "Ergebnis mit pg_proc.proconfig abgeglichen — Functions, deren search_path durch eine spätere " +
            "ALTER FUNCTION-Migration runtime-gehärtet wurde, erscheinen als ACCEPTED statt RED."
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
            .sortedBy { it.fileName.toString() }
            .toList()

        if (sqlFiles.isEmpty()) {
            return skipped("Keine *.sql-Dateien unter $migrations gefunden.", start)
        }

        val runtimeHardened: Map<String, Boolean>? = runtimeHardenedLookup()
        val runtimeAvailable = runtimeHardened != null

        val guards = guardFunctionsIn(sqlFiles)

        val findings = mutableListOf<Finding>()
        var totalFunctions = 0
        var secdefFunctions = 0
        var demotedToAccepted = 0

        for (file in sqlFiles) {
            val content = runCatching { file.readText() }.getOrNull() ?: continue
            for (match in funcRegex.findAll(content)) {
                // CREATE FUNCTION als Text in EXECUTE format('…') (DO-Block einer Migration): kein eigener Rumpf,
                // sonst würde der umgebende DO-Block dieser Function zugeschrieben.
                if (PlPgSqlHeuristics.startsInsideStringLiteral(content, match.range.first)) continue
                totalFunctions++
                val functionName = match.groupValues[1]
                val signatureAndOptions = match.groupValues[2]
                // groupValues[3] = Dollar-Tag (z. B. "", "func", "body") — nicht genutzt
                val body = match.groupValues[4]
                val fullBlock = match.value

                val isSecdef = Regex("""\bSECURITY\s+DEFINER\b""", RegexOption.IGNORE_CASE).containsMatchIn(signatureAndOptions)
                if (!isSecdef) continue
                secdefFunctions++

                val codeLoc = codeLocationOf(migrations, file, content, match.range.first, match.range.last)
                val location = "${codeLoc.displayPath}:${codeLoc.startLine}"
                val findingsForFn = mutableListOf<Finding>()

                val hasSearchPath = Regex("""\bSET\s+search_path\b""", RegexOption.IGNORE_CASE)
                    .containsMatchIn(signatureAndOptions)
                if (!hasSearchPath) {
                    val runtimeHardenedHere = runtimeHardened?.let {
                        val keyQualified = functionName.lowercase()
                        val keyBare = keyQualified.substringAfterLast('.')
                        it[keyQualified] == true || it[keyBare] == true
                    } ?: false
                    if (runtimeHardenedHere) {
                        demotedToAccepted++
                        findingsForFn += Finding(
                            CheckStatus.ACCEPTED,
                            "SECDEF '$functionName' ohne inline SET search_path — runtime gehärtet",
                            "$location — Migrationsdatei zeigt CREATE FUNCTION ohne 'SET search_path = …'. " +
                                "Der Live-Zustand (pg_proc.proconfig) enthält jedoch search_path=…, vermutlich " +
                                "gesetzt durch eine spätere ALTER FUNCTION-Migration. Achtung: ein zukünftiges " +
                                "'CREATE OR REPLACE FUNCTION' ohne inline-SET würde PROCONFIG zurücksetzen — " +
                                "sicherzustellen, dass die Härtung mitwandert (inline-Klausel oder Backstop-Migration).",
                            codeLocation = codeLoc,
                        )
                    } else {
                        findingsForFn += Finding(
                            CheckStatus.RED,
                            "SECDEF '$functionName' ohne SET search_path",
                            "$location — ohne explicit 'SET search_path = …' kann ein Angreifer mit CREATE-Rechten in einem " +
                                "anderen Schema (z. B. pg_temp) Objekte unter denselben Namen anlegen und so beliebigen Code " +
                                "im Owner-Kontext ausführen (search_path-Hijack).",
                            codeLocation = codeLoc,
                        )
                    }
                }

                val callsAuthOrRoleCheck = PlPgSqlHeuristics.hasAuthOrRoleCheck(body, guards)
                if (!callsAuthOrRoleCheck) {
                    findingsForFn += Finding(
                        CheckStatus.YELLOW,
                        "SECDEF '$functionName' ohne erkennbaren auth/role-Check",
                        "$location — Function bypasst RLS (DEFINER). Ohne expliziten auth.uid()-/role-Check " +
                            "kann jeder authentifizierte User die Function mit beliebigen Parametern aufrufen.",
                        codeLocation = codeLoc,
                    )
                }

                val unsafeExecute = PlPgSqlHeuristics.hasUnsafeFormatExecute(body)
                if (unsafeExecute) {
                    findingsForFn += Finding(
                        CheckStatus.RED,
                        "SECDEF '$functionName' verwendet format()-EXECUTE ohne USING",
                        "$location — Dynamisches SQL via EXECUTE format(…) ohne nachfolgendes USING bedeutet, dass " +
                            "Werte über String-Konkatenation eingebaut werden. Klassischer SQL-Injection-Vektor.",
                        codeLocation = codeLoc,
                    )
                }

                val executeWithLiteral = PlPgSqlHeuristics.hasConcatExecute(body)
                if (executeWithLiteral) {
                    findingsForFn += Finding(
                        CheckStatus.RED,
                        "SECDEF '$functionName' baut EXECUTE per || zusammen",
                        "$location — String-Konkatenation in EXECUTE ist SQL-Injection-anfällig. Stattdessen EXECUTE … USING \$1 nutzen.",
                        codeLocation = codeLoc,
                    )
                }

                if (findingsForFn.isEmpty()) {
                    findings += Finding(
                        CheckStatus.GREEN,
                        "SECDEF '$functionName' wirkt strukturell sauber",
                        "$location — search_path gesetzt, auth-Check vorhanden, keine offensichtliche Injection.",
                        codeLocation = codeLoc,
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

        val overlayNote = when {
            !runtimeAvailable ->
                " Runtime-Overlay inaktiv (keine Katalogquelle) — RED-Findings können False Positives sein, " +
                    "wenn spätere ALTER FUNCTION-Migrationen search_path setzen. DB-Passwort, Management-Token " +
                    "oder Snapshot bereitstellen, um den Live-Zustand abzugleichen."
            demotedToAccepted > 0 ->
                " Runtime-Overlay aktiv: $demotedToAccepted statisch-RED Finding(s) wurden zu ACCEPTED " +
                    "demoted, weil pg_proc.proconfig search_path=… enthält."
            else ->
                " Runtime-Overlay aktiv — keine Demotions nötig."
        }
        val summary = "$secdefFunctions SECDEF von $totalFunctions Functions in ${sqlFiles.size} Migrations geprüft.$overlayNote"
        return resultOf(findings, summary, start)
    }

    /**
     * Vorlauf über alle Migrations: die jeweils letzte Fassung jeder Function (Dateien nach Namen
     * sortiert = Migrationsreihenfolge) und daraus die projekteigenen Guard-Functions.
     */
    private fun guardFunctionsIn(sqlFiles: List<Path>): Set<String> {
        val latest = linkedMapOf<String, PlPgSqlHeuristics.FunctionSource>()
        for (file in sqlFiles) {
            val content = runCatching { file.readText() }.getOrNull() ?: continue
            for (match in funcRegex.findAll(content)) {
                if (PlPgSqlHeuristics.startsInsideStringLiteral(content, match.range.first)) continue
                val name = match.groupValues[1].substringAfterLast('.').lowercase()
                val args = match.value.substringAfter('(').substringBefore(')')
                latest[name] = PlPgSqlHeuristics.FunctionSource(
                    name = name,
                    hasNoArgs = args.isBlank(),
                    returnsSimpleScalar = PlPgSqlHeuristics.returnsSimpleScalar(match.groupValues[2] + " "),
                    body = match.groupValues[4],
                )
            }
        }
        return PlPgSqlHeuristics.guardFunctions(latest.values)
    }

    private fun codeLocationOf(root: Path, file: Path, content: String, startOffset: Int, endOffset: Int): CodeLocation {
        val rel = root.relativize(file).toString()
        val startLine = content.substring(0, startOffset.coerceAtMost(content.length)).count { it == '\n' } + 1
        val endLine = content.substring(0, endOffset.coerceAtMost(content.length)).count { it == '\n' } + 1
        return CodeLocation(file = file, displayPath = rel, startLine = startLine, endLine = endLine)
    }

    companion object {
        // Liest pg_proc + pg_namespace und liefert für jede SECDEF-Function einen Map-Eintrag,
        // ob ihre proconfig einen 'search_path=…'-Eintrag enthält. Indiziert beide Schreibweisen
        // (qualifiziert 'schema.name' und bare 'name'), damit die statische Regex-Erfassung
        // (die das Schema oft weglässt) zuverlässig auf den Runtime-Eintrag mappen kann.
        // Bei mehreren Overloads gilt: ANY-overload-hardened ⇒ als gehärtet werten (False-Positive-Vermeidung).
        // Gibt null zurück, wenn keine Katalogquelle verfügbar ist oder die Query scheitert — dann fällt der Check
        // auf rein-statisches Verhalten zurück.
        private fun loadRuntimeHardenedSecdef(catalog: CatalogAccess): Map<String, Boolean>? {
            val source = catalog.sourceOrNull ?: return null
            return runCatching {
                val map = mutableMapOf<String, Boolean>()
                for (row in source.query(CatalogQuery.SECDEF_FUNCTIONS)) {
                    val name = row.string("name") ?: continue
                    if (name.isBlank()) continue
                    val schema = row.string("schema_name") ?: ""
                    val hasSearchPath = row.textArray("proconfig")
                        .any { it.startsWith("search_path=", ignoreCase = true) }
                    map.merge("$schema.$name".lowercase(), hasSearchPath) { old, new -> old || new }
                    map.merge(name.lowercase(), hasSearchPath) { old, new -> old || new }
                }
                map
            }.getOrNull()
        }
    }
}

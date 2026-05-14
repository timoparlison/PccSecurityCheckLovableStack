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

@CheckId(name = "edge-fn-audit")
class EdgeFunctionAuditCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    @Suppress("UNUSED_PARAMETER") httpClient: cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient =
        cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "Edge-Function Audit (CORS, SQL-Inj, Auth, Secrets, Validation)"
    override val description =
        "Scannt lokale Edge-Functions (*.ts/*.tsx) heuristisch nach typischen Anti-Patterns: " +
            "permissive CORS, SQL-Injection-Vektoren in rpc/template-Strings, fehlender Auth-Check vor " +
            "DB-Writes, Logging von Secrets/Authorization-Headern, fehlende Input-Validation."
    override val category = "Supabase / Edge Functions"

    @OptIn(kotlin.io.path.ExperimentalPathApi::class)
    override fun run(): CheckResult {
        val start = Instant.now()
        val root = config.functionsPath
            ?: return skipped("functions.path ist nicht gesetzt — Check übersprungen.", start)

        if (!Files.isDirectory(root)) {
            return skipped("functions.path zeigt nicht auf ein Verzeichnis: $root", start)
        }

        val tsFiles = root.walk()
            .filter { it.isRegularFile() && (it.extension == "ts" || it.extension == "tsx") }
            .toList()

        if (tsFiles.isEmpty()) {
            return skipped("Keine *.ts/*.tsx-Dateien unter $root gefunden.", start)
        }

        val findings = mutableListOf<Finding>()
        for (file in tsFiles) {
            val raw = runCatching { file.readText() }.getOrNull() ?: continue
            val rel = root.relativize(file).toString()
            scanFile(rel, raw, findings)
        }

        // Zusammenfassende GREENs für Functions ohne Findings — pragmatisch: nur pro File einen, falls nichts gefunden
        val filesWithIssues = findings.mapNotNull { Regex("""^([^:]+):""").find(it.title)?.groupValues?.get(1) }.toSet()
        val cleanFiles = tsFiles.map { root.relativize(it).toString() }.filterNot { it in filesWithIssues }
        for (f in cleanFiles) {
            findings += Finding(
                CheckStatus.GREEN,
                "$f: keine Heuristik-Treffer",
                "Datei unauffällig (Heuristik — kein Beweis von Korrektheit).",
            )
        }

        val red = findings.count { it.severity == CheckStatus.RED }
        val yellow = findings.count { it.severity == CheckStatus.YELLOW }
        val summary = "${tsFiles.size} TS-Datei(en) gescannt: $red kritisch, $yellow Warnung(en), ${cleanFiles.size} unauffällig."
        return resultOf(findings, summary, start)
    }

    private fun scanFile(rel: String, raw: String, findings: MutableList<Finding>) {
        val src = stripBlockComments(raw)

        // ---- CORS ----
        val corsWildcard = Regex("""['"]Access-Control-Allow-Origin['"]\s*[,:]\s*['"]\*['"]""", RegexOption.IGNORE_CASE)
        val corsCreds = Regex("""['"]Access-Control-Allow-Credentials['"]\s*[,:]\s*['"]?true['"]?""", RegexOption.IGNORE_CASE)
        val corsWildcardHit = corsWildcard.find(src)
        if (corsWildcardHit != null) {
            val hasCreds = corsCreds.containsMatchIn(src)
            if (hasCreds) {
                findings += Finding(
                    CheckStatus.RED,
                    "$rel: CORS '*' + Allow-Credentials: true",
                    "Diese Kombination ist explizit verboten und wird von Browsern ignoriert — Symptom für eine " +
                        "Misconfig. Bei Production-Frontends mit Cookies/Authorization-Headern müssen erlaubte Origins " +
                        "explizit aufgelistet sein.",
                    evidence = lineAround(raw, corsWildcardHit.range.first),
                )
            } else {
                findings += Finding(
                    CheckStatus.YELLOW,
                    "$rel: CORS '*' Wildcard erlaubt",
                    "Access-Control-Allow-Origin: * erlaubt Cross-Origin-Reads von beliebigen Seiten. Bei rein " +
                        "öffentlichen Functions ggf. OK; bei allem mit Authorization-Header → explizite Origin-Whitelist.",
                    evidence = lineAround(raw, corsWildcardHit.range.first),
                )
            }
        }

        // ---- SQL injection: template literal in rpc-Args ----
        val rpcTemplate = Regex("""\.rpc\(\s*`[^`]*\$\{[^}]+\}[^`]*`""", RegexOption.DOT_MATCHES_ALL)
        rpcTemplate.find(src)?.let { m ->
            findings += Finding(
                CheckStatus.RED,
                "$rel: Template-Literal mit \${} im .rpc(...)-Call",
                "Der RPC-Functions-Name (oder Args) wird per Template-Literal mit User-Input zusammengebaut. " +
                    "PostgREST-RPC selbst ist zwar parametrisiert, aber dieser Pattern ist typisch für " +
                    "dynamische Function-Wahl oder SQL-Konstruktion und sehr fehleranfällig.",
                evidence = lineAround(raw, m.range.first),
            )
        }

        // Generic raw-SQL danger pattern: pg client query mit Template-Literal
        val rawQueryTemplate = Regex("""\.query\(\s*`[^`]*\$\{[^}]+\}[^`]*`""", RegexOption.DOT_MATCHES_ALL)
        rawQueryTemplate.find(src)?.let { m ->
            findings += Finding(
                CheckStatus.RED,
                "$rel: .query(`…\${}…`) — String-Interpolation in SQL",
                "Direkte String-Interpolation in einem Postgres-Query ist klassische SQL-Injection. " +
                    "Stattdessen parametrisierte Calls (\$1, \$2 …) nutzen.",
                evidence = lineAround(raw, m.range.first),
            )
        }

        // ---- Service-Role-Client ohne Auth-Check vor Writes ----
        val hasServiceRoleClient = Regex(
            """createClient\([^)]*SUPABASE_SERVICE_ROLE_KEY""",
            RegexOption.DOT_MATCHES_ALL,
        ).containsMatchIn(src)
        val hasAuthCheck = Regex(
            """auth\.getUser\(|verifyJWT\(|jwt\.verify\(""",
            RegexOption.IGNORE_CASE,
        ).containsMatchIn(src)
        val hasWriteOp = Regex(
            """\.(insert|update|delete|upsert)\(""",
            RegexOption.IGNORE_CASE,
        ).containsMatchIn(src)

        if (hasServiceRoleClient && hasWriteOp && !hasAuthCheck) {
            findings += Finding(
                CheckStatus.RED,
                "$rel: Service-Role-Client führt Writes ohne erkennbaren Auth-Check aus",
                "Die Function nutzt SUPABASE_SERVICE_ROLE_KEY (umgeht RLS) und macht Inserts/Updates/Deletes, " +
                    "ohne dass davor auth.getUser()/JWT-Verify im Code zu sehen ist. Jeder, der die Function-URL " +
                    "kennt, kann beliebige DB-Writes triggern.",
            )
        } else if (hasServiceRoleClient && !hasAuthCheck) {
            findings += Finding(
                CheckStatus.YELLOW,
                "$rel: Service-Role-Client ohne erkennbaren Auth-Check",
                "Die Function nutzt SUPABASE_SERVICE_ROLE_KEY ohne sichtbare Authentication. Bei reinen Reads " +
                    "ggf. OK (z. B. öffentliche Aggregationen), sonst Auth nachrüsten.",
            )
        }

        // ---- Secret/Header logging ----
        val secretLog = Regex(
            """console\.(log|info|warn|debug|error)\([^)]*\b(authorization|apikey|token|secret|password|jwt|service[_-]?role)""",
            RegexOption.IGNORE_CASE,
        )
        secretLog.findAll(src).take(3).forEach { m ->
            findings += Finding(
                CheckStatus.YELLOW,
                "$rel: möglicher Secret-/Header-Log",
                "Ein console.log-Call enthält ein Schlüsselwort, das auf das Loggen sensibler Daten hindeutet. " +
                    "Edge-Function-Logs sind in Supabase einsehbar — Secrets dort sind ein Leck.",
                evidence = lineAround(raw, m.range.first),
            )
        }

        // ---- Input validation ----
        val hasReqJson = Regex("""req\.json\(\)|request\.json\(\)""").containsMatchIn(src)
        val hasSchemaValidator = Regex(
            """from\s+['"]https?://[^'"]+/zod|from\s+['"]zod['"]|from\s+['"]yup['"]|from\s+['"]joi['"]|from\s+['"]valibot['"]""",
            RegexOption.IGNORE_CASE,
        ).containsMatchIn(src)
        if (hasReqJson && !hasSchemaValidator) {
            findings += Finding(
                CheckStatus.YELLOW,
                "$rel: req.json() ohne Schema-Validator",
                "Der Function-Body wird per JSON.parse übernommen, ohne dass ein Validator (zod/yup/joi/valibot) " +
                    "importiert wird. Eingaben sind type-mäßig 'any' — leichte Quelle für Type-Confusion / unerwartete Felder.",
            )
        }
    }

    private fun stripBlockComments(src: String): String =
        Regex("/\\*[\\s\\S]*?\\*/").replace(src, "")

    private fun lineAround(raw: String, charOffset: Int): String {
        val safe = charOffset.coerceIn(0, raw.length - 1)
        val lineStart = raw.lastIndexOf('\n', safe).let { if (it < 0) 0 else it + 1 }
        val lineEnd = raw.indexOf('\n', safe).let { if (it < 0) raw.length else it }
        val lineNo = raw.substring(0, lineStart).count { it == '\n' } + 1
        return "Zeile $lineNo: ${raw.substring(lineStart, lineEnd).trim().take(240)}"
    }
}

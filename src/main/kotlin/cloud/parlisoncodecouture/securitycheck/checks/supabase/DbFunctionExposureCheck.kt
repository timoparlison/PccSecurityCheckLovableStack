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
import cloud.parlisoncodecouture.securitycheck.db.PostgresQueryClient
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import kotlin.io.path.extension
import kotlin.io.path.isRegularFile
import kotlin.io.path.readText
import kotlin.io.path.walk

/**
 * Live-Gegenstück zu plpgsql-secdef-audit: liest die Functions im public-Schema direkt aus pg_proc
 * und bewertet sie nach ihrer tatsächlichen Aufrufbarkeit über PostgREST (POST /rest/v1/rpc/<name>).
 *
 * Entscheidend ist has_function_privilege('anon'|'authenticated', …, 'EXECUTE') — das berücksichtigt
 * GRANTs, Default-Privileges und den impliziten PUBLIC-Default in einem Zug. Die Migrations dienen
 * nur noch als Fundstelle (CodeLocation), nicht als Wahrheit.
 */
@CheckId(name = "db-function-exposure")
class DbFunctionExposureCheck(
    private val config: SupabaseConfig,
) : SecurityCheck {
    override val name = "DB-Functions: Live-Aufrufbarkeit (RPC)"
    override val description =
        "Liest alle Functions im public-Schema live aus pg_proc (read-only, SSL) inkl. EXECUTE-Rechten " +
            "für anon/authenticated, proconfig (search_path) und dem aktuellen Quelltext. SECURITY DEFINER-" +
            "Functions, die per /rest/v1/rpc aufrufbar sind, werden auf fehlenden search_path, fehlenden " +
            "auth-Check und unsicheres dynamisches SQL geprüft. Fundstellen werden, falls vorhanden, den " +
            "Migrations zugeordnet. Die Functions werden NICHT aufgerufen."
    override val category = "Supabase / DB Functions"

    enum class Exposure(val label: String) {
        ANON("anon (ohne Login)"),
        AUTHENTICATED("authenticated (jeder eingeloggte Nutzer)"),
        NONE("nur service_role/Owner"),
    }

    data class LiveFunction(
        val name: String,
        val identityArgs: String,
        val securityDefiner: Boolean,
        val proconfig: List<String>,
        val owner: String,
        val language: String,
        val anonExecute: Boolean,
        val authenticatedExecute: Boolean,
        val definition: String,
    ) {
        val signature: String get() = "public.$name($identityArgs)"
        val exposure: Exposure
            get() = when {
                anonExecute -> Exposure.ANON
                authenticatedExecute -> Exposure.AUTHENTICATED
                else -> Exposure.NONE
            }
        val hasPinnedSearchPath: Boolean
            get() = proconfig.any { it.startsWith("search_path=", ignoreCase = true) }
    }

    override fun run(): CheckResult {
        val start = Instant.now()
        if (!config.hasDbAccess) {
            return skipped(
                "DB-Zugang fehlt. Setze SUPABASE_DB_PASSWORD (Env) bzw. -Dsupabase.db.password=... und " +
                    "optional db.host in den properties.",
                start,
            )
        }

        val functions = try {
            PostgresQueryClient(config).use { client -> client.query(FUNCTIONS_SQL, ::mapRow) }
        } catch (e: Exception) {
            return resultOf(
                findings = listOf(
                    Finding(
                        CheckStatus.ERROR,
                        "DB-Query fehlgeschlagen",
                        "JDBC-Aufruf nach Postgres fehlgeschlagen: ${e.message ?: e::class.simpleName}",
                    ),
                ),
                summary = "DB nicht erreichbar oder Query fehlgeschlagen.",
                start = start,
            )
        }

        if (functions.isEmpty()) {
            return resultOf(
                findings = listOf(Finding(CheckStatus.GREEN, "Keine Functions im public-Schema", "Keine RPC-Oberfläche vorhanden.")),
                summary = "0 Functions in public.",
                start = start,
            )
        }

        val migrationIndex = MigrationIndex.load(config.migrationsPath)
        val findings = mutableListOf<Finding>()

        val secdef = functions.filter { it.securityDefiner }
        for (fn in secdef) {
            findings += evaluateSecdef(fn, migrationIndex?.locate(fn.name), migrationIndex != null)
        }

        val invokerAnon = functions.filter { !it.securityDefiner && it.anonExecute }
        if (invokerAnon.isNotEmpty()) {
            findings += Finding(
                CheckStatus.GREEN,
                "${invokerAnon.size} SECURITY INVOKER-Function(s) von anon aufrufbar (Info)",
                "Diese Functions laufen mit den Rechten des Aufrufers — RLS greift. Sie sind in der Regel " +
                    "unkritisch, gehören aber zur öffentlichen RPC-Oberfläche. Nicht benötigte Functions " +
                    "sollten per REVOKE EXECUTE … FROM PUBLIC, anon geschlossen werden.",
                evidence = invokerAnon.joinToString("\n") { it.signature },
            )
        }

        val secdefAnon = secdef.count { it.exposure == Exposure.ANON }
        val secdefAuth = secdef.count { it.exposure == Exposure.AUTHENTICATED }
        val summary = "${functions.size} Function(s) in public, davon ${secdef.size} SECURITY DEFINER " +
            "($secdefAnon von anon, $secdefAuth nur von authenticated aufrufbar). " +
            "${invokerAnon.size} INVOKER-Function(s) von anon aufrufbar." +
            if (migrationIndex == null) " Kein migrations.path — ohne Fundstellen-Zuordnung." else ""
        return resultOf(findings, summary, start)
    }

    private fun mapRow(rs: java.sql.ResultSet): LiveFunction {
        val configArray = rs.getArray("proconfig")?.array as? Array<*>
        return LiveFunction(
            name = rs.getString("proname"),
            identityArgs = rs.getString("args") ?: "",
            securityDefiner = rs.getBoolean("prosecdef"),
            proconfig = configArray?.mapNotNull { it?.toString() } ?: emptyList(),
            owner = rs.getString("owner") ?: "?",
            language = rs.getString("lanname") ?: "?",
            anonExecute = rs.getBoolean("anon_execute"),
            authenticatedExecute = rs.getBoolean("auth_execute"),
            definition = rs.getString("definition") ?: "",
        )
    }

    /** Index der CREATE FUNCTION-Stellen in den Migrations — die zuletzt angelegte Version gewinnt. */
    internal class MigrationIndex(private val locations: Map<String, CodeLocation>) {
        fun locate(functionName: String): CodeLocation? = locations[functionName.lowercase()]

        companion object {
            private val createFunction = Regex(
                """CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(?:"?(\w+)"?\s*\.\s*)?"?(\w+)"?\s*\(""",
                RegexOption.IGNORE_CASE,
            )

            @OptIn(kotlin.io.path.ExperimentalPathApi::class)
            fun load(migrations: Path?): MigrationIndex? {
                if (migrations == null || !Files.isDirectory(migrations)) return null
                val locations = mutableMapOf<String, CodeLocation>()
                // Supabase-Migrations tragen einen Zeitstempel-Präfix → lexikografisch = chronologisch.
                val files = migrations.walk()
                    .filter { it.isRegularFile() && it.extension.equals("sql", ignoreCase = true) }
                    .sortedBy { it.toString() }
                for (file in files) {
                    val content = runCatching { file.readText() }.getOrNull() ?: continue
                    for (match in createFunction.findAll(content)) {
                        val schema = match.groupValues[1].lowercase()
                        if (schema.isNotEmpty() && schema != "public") continue
                        val line = content.substring(0, match.range.first).count { it == '\n' } + 1
                        locations[match.groupValues[2].lowercase()] = CodeLocation(
                            file = file,
                            displayPath = migrations.relativize(file).toString(),
                            startLine = line,
                        )
                    }
                }
                return MigrationIndex(locations)
            }
        }
    }

    companion object {
        // Nur prokind='f': Procedures sind über PostgREST nicht per RPC aufrufbar, Trigger-Functions
        // ebenfalls nicht. Functions, die zu einer Extension gehören, bleiben außen vor (eigener Check).
        private val FUNCTIONS_SQL = """
            SELECT p.proname,
                   pg_get_function_identity_arguments(p.oid)                  AS args,
                   p.prosecdef,
                   p.proconfig,
                   pg_get_userbyid(p.proowner)                                AS owner,
                   l.lanname,
                   has_function_privilege('anon', p.oid, 'EXECUTE')          AS anon_execute,
                   has_function_privilege('authenticated', p.oid, 'EXECUTE') AS auth_execute,
                   pg_get_functiondef(p.oid)                                  AS definition
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            JOIN pg_language  l ON l.oid = p.prolang
            WHERE n.nspname = 'public'
              AND p.prokind = 'f'
              AND p.prorettype NOT IN ('trigger'::regtype, 'event_trigger'::regtype)
              AND NOT EXISTS (
                  SELECT 1 FROM pg_depend d
                  WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
              )
            ORDER BY p.proname, args
        """.trimIndent()

        /** Bewertet eine SECURITY DEFINER-Function; genau ein Finding pro Function. */
        internal fun evaluateSecdef(fn: LiveFunction, codeLoc: CodeLocation?, migrationsScanned: Boolean): Finding {
            val exposed = fn.exposure != Exposure.NONE
            val problems = mutableListOf<Pair<CheckStatus, String>>()

            if (!fn.hasPinnedSearchPath) {
                problems += (if (exposed) CheckStatus.RED else CheckStatus.YELLOW) to
                    "Kein fester search_path in proconfig — search_path-Hijack möglich."
            }
            if (PlPgSqlHeuristics.hasUnsafeFormatExecute(fn.definition) || PlPgSqlHeuristics.hasConcatExecute(fn.definition)) {
                problems += (if (exposed) CheckStatus.RED else CheckStatus.YELLOW) to
                    "Dynamisches SQL per EXECUTE ohne USING bzw. per ||-Konkatenation — SQL-Injection-Vektor."
            }
            val hasAuthCheck = PlPgSqlHeuristics.hasAuthOrRoleCheck(fn.definition)
            when {
                fn.exposure == Exposure.ANON && !hasAuthCheck -> problems += CheckStatus.RED to
                    "Von anon aufrufbar und kein erkennbarer auth.uid()/role-Check: jeder Besucher kann die " +
                    "Function mit beliebigen Parametern und Owner-Rechten (RLS umgangen) ausführen."
                fn.exposure == Exposure.AUTHENTICATED && !hasAuthCheck -> problems += CheckStatus.YELLOW to
                    "Kein erkennbarer auth.uid()/role-Check: jeder eingeloggte Nutzer kann die Function mit " +
                    "beliebigen Parametern (z. B. fremden IDs) ausführen."
                fn.exposure == Exposure.ANON -> problems += CheckStatus.YELLOW to
                    "Von anon aufrufbar, obwohl ein auth-Check existiert — vermutlich unnötig offen."
            }

            val location = when {
                codeLoc != null -> "Definiert in ${codeLoc.displayPath}:${codeLoc.startLine}."
                migrationsScanned -> "Keine CREATE FUNCTION in den Migrations gefunden — vermutlich am Repo vorbei angelegt."
                else -> null
            }
            val evidence = buildString {
                appendLine("Signatur:   ${fn.signature}")
                appendLine("Owner:      ${fn.owner}")
                appendLine("Sprache:    ${fn.language}")
                appendLine("proconfig:  ${fn.proconfig.joinToString("; ").ifEmpty { "(leer)" }}")
                append("EXECUTE:    anon=${yesNo(fn.anonExecute)}, authenticated=${yesNo(fn.authenticatedExecute)}")
            }

            if (problems.isEmpty()) {
                return Finding(
                    CheckStatus.GREEN,
                    "SECDEF ${fn.signature}: aufrufbar für ${fn.exposure.label}, strukturell sauber",
                    listOfNotNull(
                        "search_path gesetzt, auth-Check vorhanden bzw. nicht öffentlich aufrufbar, keine offensichtliche Injection.",
                        location,
                    ).joinToString(" "),
                    evidence = evidence,
                    codeLocation = codeLoc,
                )
            }

            val detail = buildString {
                appendLine("Aufrufbar für: ${fn.exposure.label}.")
                problems.forEach { (_, text) -> appendLine("• $text") }
                location?.let { appendLine(it) }
                append("Fix: ").append(remediation(fn))
            }
            return Finding(
                CheckStatus.worstOf(problems.map { it.first }),
                "SECDEF ${fn.signature}: aufrufbar für ${fn.exposure.label}",
                detail,
                evidence = evidence,
                codeLocation = codeLoc,
            )
        }

        private fun remediation(fn: LiveFunction): String {
            val steps = mutableListOf<String>()
            val target = "public.${fn.name}(${fn.identityArgs})"
            if (fn.exposure == Exposure.ANON) {
                // REVOKE nur von anon reicht nicht: EXECUTE hängt per Default auch an PUBLIC.
                steps += "REVOKE EXECUTE ON FUNCTION $target FROM PUBLIC, anon; " +
                    "(falls eingeloggte Nutzer sie brauchen: GRANT EXECUTE ON FUNCTION $target TO authenticated;)"
            }
            if (!fn.hasPinnedSearchPath) steps += "ALTER FUNCTION $target SET search_path = '';"
            if (!PlPgSqlHeuristics.hasAuthOrRoleCheck(fn.definition) && fn.exposure != Exposure.NONE) {
                steps += "Im Rumpf den Aufrufer per auth.uid() gegen die übergebenen Parameter prüfen."
            }
            if (PlPgSqlHeuristics.hasUnsafeFormatExecute(fn.definition) || PlPgSqlHeuristics.hasConcatExecute(fn.definition)) {
                steps += "Dynamisches SQL auf EXECUTE … USING umstellen."
            }
            return steps.joinToString(" ")
        }

        private fun yesNo(b: Boolean) = if (b) "ja" else "nein"
    }
}

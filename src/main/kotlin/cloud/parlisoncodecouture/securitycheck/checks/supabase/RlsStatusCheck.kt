package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.Finding
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.core.resultOf
import cloud.parlisoncodecouture.securitycheck.core.skipped
import cloud.parlisoncodecouture.securitycheck.db.PostgresQueryClient
import java.time.Instant

@CheckId(name = "rls-status")
class RlsStatusCheck(
    private val config: SupabaseConfig,
) : SecurityCheck {
    override val name = "RLS-Status & API-Rechte pro Relation (public-Schema)"
    override val description =
        "Liest pg_class/pg_policy direkt via JDBC (read-only, SSL) für alle Tabellen, Views, Materialized " +
            "Views und Foreign Tables im public-Schema: ist RLS aktiv, wie viele Policies gibt es, laufen " +
            "Views mit security_invoker, und welche Rechte (SELECT/INSERT/UPDATE/DELETE) haben anon und " +
            "authenticated tatsächlich? Es werden KEINE Objekte im Zielsystem angelegt."
    override val category = "Supabase / RLS"

    enum class Kind(val label: String) {
        TABLE("Tabelle"),
        PARTITIONED("Partitionierte Tabelle"),
        VIEW("View"),
        MATVIEW("Materialized View"),
        FOREIGN("Foreign Table"),
    }

    /** Rechte einer Rolle auf der Relation; SELECT/INSERT/UPDATE zählen auch auf Spaltenebene. */
    data class Privileges(val select: Boolean, val insert: Boolean, val update: Boolean, val delete: Boolean) {
        val any: Boolean get() = select || insert || update || delete
        override fun toString(): String =
            listOfNotNull("SELECT".takeIf { select }, "INSERT".takeIf { insert }, "UPDATE".takeIf { update }, "DELETE".takeIf { delete })
                .joinToString(", ").ifEmpty { "—" }
    }

    data class Relation(
        val name: String,
        val kind: Kind,
        val rlsEnabled: Boolean,
        val rlsForced: Boolean,
        val policyCount: Int,
        val options: List<String>,
        val anon: Privileges,
        val authenticated: Privileges,
    ) {
        /** security_invoker ist ein Boolean-Reloption; Postgres speichert den Wert so, wie er gesetzt wurde. */
        val securityInvoker: Boolean
            get() = options.any { opt ->
                val (key, value) = opt.split('=', limit = 2).let { it[0] to it.getOrElse(1) { "true" } }
                key.equals("security_invoker", ignoreCase = true) &&
                    value.lowercase() in setOf("true", "on", "1", "yes", "t", "y")
            }
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

        val relations = try {
            PostgresQueryClient(config).use { client -> client.query(RELATIONS_SQL, ::mapRow) }
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

        if (relations.isEmpty()) {
            return resultOf(
                findings = listOf(Finding(CheckStatus.GREEN, "Keine Relationen im public-Schema", "Nichts zu prüfen.")),
                summary = "0 Relationen in public.",
                start = start,
            )
        }

        val findings = relations.map(::evaluate)
        val byKind = relations.groupingBy { it.kind }.eachCount()
            .entries.joinToString(", ") { (kind, n) -> "$n ${kind.label}" }
        val red = findings.count { it.severity == CheckStatus.RED }
        val yellow = findings.count { it.severity == CheckStatus.YELLOW }
        val summary = "${relations.size} Relation(en) ($byKind): $red kritisch, $yellow Warnung(en)."
        return resultOf(findings, summary, start)
    }

    private fun mapRow(rs: java.sql.ResultSet): Relation {
        val optionsArray = rs.getArray("reloptions")?.array as? Array<*>
        return Relation(
            name = rs.getString("relname"),
            kind = when (rs.getString("relkind")) {
                "p" -> Kind.PARTITIONED
                "v" -> Kind.VIEW
                "m" -> Kind.MATVIEW
                "f" -> Kind.FOREIGN
                else -> Kind.TABLE
            },
            rlsEnabled = rs.getBoolean("relrowsecurity"),
            rlsForced = rs.getBoolean("relforcerowsecurity"),
            policyCount = rs.getInt("policy_count"),
            options = optionsArray?.mapNotNull { it?.toString() } ?: emptyList(),
            anon = Privileges(
                rs.getBoolean("anon_select"), rs.getBoolean("anon_insert"),
                rs.getBoolean("anon_update"), rs.getBoolean("anon_delete"),
            ),
            authenticated = Privileges(
                rs.getBoolean("auth_select"), rs.getBoolean("auth_insert"),
                rs.getBoolean("auth_update"), rs.getBoolean("auth_delete"),
            ),
        )
    }

    companion object {
        private val RELATIONS_SQL = """
            SELECT c.relname,
                   c.relkind::text                                            AS relkind,
                   c.relrowsecurity,
                   c.relforcerowsecurity,
                   (SELECT count(*) FROM pg_policy pol WHERE pol.polrelid = c.oid) AS policy_count,
                   c.reloptions,
                   has_any_column_privilege('anon', c.oid, 'SELECT')          AS anon_select,
                   has_any_column_privilege('anon', c.oid, 'INSERT')          AS anon_insert,
                   has_any_column_privilege('anon', c.oid, 'UPDATE')          AS anon_update,
                   has_table_privilege('anon', c.oid, 'DELETE')               AS anon_delete,
                   has_any_column_privilege('authenticated', c.oid, 'SELECT') AS auth_select,
                   has_any_column_privilege('authenticated', c.oid, 'INSERT') AS auth_insert,
                   has_any_column_privilege('authenticated', c.oid, 'UPDATE') AS auth_update,
                   has_table_privilege('authenticated', c.oid, 'DELETE')      AS auth_delete
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
            ORDER BY c.relname
        """.trimIndent()

        internal fun evaluate(rel: Relation): Finding {
            val label = "${rel.kind.label} 'public.${rel.name}'"
            val evidence = buildString {
                appendLine("anon:          ${rel.anon}")
                appendLine("authenticated: ${rel.authenticated}")
                append("RLS: ${if (rel.rlsEnabled) "an" else "aus"}")
                if (rel.rlsForced) append(" (FORCE)")
                append(", Policies: ${rel.policyCount}")
                if (rel.options.isNotEmpty()) append(", Optionen: ${rel.options.joinToString("; ")}")
            }
            val (severity, title, detail) = when (rel.kind) {
                Kind.TABLE, Kind.PARTITIONED -> evaluateTable(rel, label)
                Kind.VIEW -> evaluateView(rel, label)
                Kind.MATVIEW, Kind.FOREIGN -> evaluateWithoutRls(rel, label)
            }
            return Finding(severity, title, detail, evidence = evidence)
        }

        private fun evaluateTable(rel: Relation, label: String): Triple<CheckStatus, String, String> = when {
            !rel.rlsEnabled && (rel.anon.any || rel.authenticated.any) -> Triple(
                CheckStatus.RED,
                "$label: RLS deaktiviert, API-Rechte vorhanden",
                "Ohne Row-Level-Security gelten die GRANTs ungefiltert: ${whoCan(rel)} " +
                    "Fix: ALTER TABLE public.${rel.name} ENABLE ROW LEVEL SECURITY; und passende Policies anlegen " +
                    "— oder die Rechte per REVOKE entziehen, falls die Tabelle nicht über die API erreichbar sein soll.",
            )
            !rel.rlsEnabled -> Triple(
                CheckStatus.YELLOW,
                "$label: RLS deaktiviert (derzeit ohne API-Rechte)",
                "anon und authenticated haben aktuell keine Rechte — über die API nicht erreichbar. Ein späteres " +
                    "GRANT (oder geänderte Default-Privileges) würde die Tabelle aber sofort ungeschützt öffnen. " +
                    "Defense in Depth: RLS trotzdem aktivieren.",
            )
            rel.policyCount == 0 -> Triple(
                CheckStatus.YELLOW,
                "$label: RLS aktiv, aber 0 Policies",
                "Die Tabelle ist für anon/authenticated effektiv gesperrt. Wenn Zugriff vorgesehen war, fehlen Policies.",
            )
            else -> Triple(
                CheckStatus.GREEN,
                "$label: RLS aktiv mit ${rel.policyCount} Policy/Policies",
                "Strukturell in Ordnung — die Policy-Logik selbst wird von permissive-policies geprüft.",
            )
        }

        private fun evaluateView(rel: Relation, label: String): Triple<CheckStatus, String, String> = when {
            rel.securityInvoker -> Triple(
                CheckStatus.GREEN,
                "$label: security_invoker aktiv",
                "Die View läuft mit den Rechten des Aufrufers — RLS der zugrunde liegenden Tabellen greift.",
            )
            !rel.anon.any && !rel.authenticated.any -> Triple(
                CheckStatus.GREEN,
                "$label: ohne security_invoker, aber keine API-Rechte",
                "Die View würde RLS umgehen, ist für anon/authenticated aber nicht lesbar. " +
                    "Empfehlung trotzdem: ALTER VIEW public.${rel.name} SET (security_invoker = true);",
            )
            else -> Triple(
                if (rel.anon.any) CheckStatus.RED else CheckStatus.YELLOW,
                "$label: umgeht RLS (kein security_invoker)",
                "Views laufen per Default mit den Rechten ihres Owners (meist postgres) — RLS auf den " +
                    "zugrunde liegenden Tabellen wird dabei nicht angewendet. ${whoCan(rel)} " +
                    "Fix: ALTER VIEW public.${rel.name} SET (security_invoker = true); oder Rechte per REVOKE entziehen.",
            )
        }

        private fun evaluateWithoutRls(rel: Relation, label: String): Triple<CheckStatus, String, String> = when {
            !rel.anon.any && !rel.authenticated.any -> Triple(
                CheckStatus.GREEN,
                "$label: keine API-Rechte",
                "${rel.kind.label}s unterstützen kein RLS; ohne Rechte für anon/authenticated ist das unkritisch.",
            )
            else -> Triple(
                if (rel.anon.any) CheckStatus.RED else CheckStatus.YELLOW,
                "$label: über die API erreichbar, kein RLS möglich",
                "${rel.kind.label}s unterstützen kein RLS — die GRANTs sind der einzige Schutz. ${whoCan(rel)} " +
                    "Fix: REVOKE ALL ON public.${rel.name} FROM anon, authenticated; bzw. in ein nicht " +
                    "exponiertes Schema verschieben und über eine Function mit Auth-Check bereitstellen.",
            )
        }

        private fun whoCan(rel: Relation): String = listOfNotNull(
            "anon (ohne Login) darf ${rel.anon}.".takeIf { rel.anon.any },
            "authenticated darf ${rel.authenticated}.".takeIf { rel.authenticated.any },
        ).joinToString(" ")
    }
}

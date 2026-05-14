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
    override val name = "RLS-Status pro Tabelle (public-Schema)"
    override val description =
        "Liest pg_class.relrowsecurity + pg_policy direkt via JDBC (read-only, SSL) und meldet für jede " +
            "public-Tabelle: ist RLS aktiv und wie viele Policies hängen dran? Es werden KEINE Functions " +
            "im Zielsystem angelegt — der Check ist eine reine read-only Query."
    override val category = "Supabase / RLS"

    override fun run(): CheckResult {
        val start = Instant.now()
        if (!config.hasDbAccess) {
            return skipped(
                "DB-Zugang fehlt. Setze SUPABASE_DB_PASSWORD (Env) bzw. -Dsupabase.db.password=... und " +
                    "optional db.host in den properties.",
                start,
            )
        }

        val rows = try {
            PostgresQueryClient(config).use { client ->
                client.query(
                    """
                    SELECT
                        n.nspname AS schema_name,
                        c.relname AS table_name,
                        c.relrowsecurity AS rls_enabled,
                        (SELECT count(*) FROM pg_policy WHERE polrelid = c.oid) AS policy_count
                    FROM pg_class c
                    JOIN pg_namespace n ON c.relnamespace = n.oid
                    WHERE c.relkind = 'r' AND n.nspname = 'public'
                    ORDER BY c.relname
                    """.trimIndent(),
                ) { rs ->
                    Triple(
                        rs.getString("table_name"),
                        rs.getBoolean("rls_enabled"),
                        rs.getInt("policy_count"),
                    )
                }
            }
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

        if (rows.isEmpty()) {
            return resultOf(
                findings = listOf(Finding(CheckStatus.GREEN, "Keine Tabellen im public-Schema", "Nichts zu prüfen.")),
                summary = "0 Tabellen in public.",
                start = start,
            )
        }

        val findings = mutableListOf<Finding>()
        var off = 0; var lockedOut = 0; var ok = 0
        for ((table, rlsEnabled, policyCount) in rows) {
            when {
                !rlsEnabled -> {
                    findings += Finding(
                        CheckStatus.RED,
                        "Tabelle 'public.$table': RLS deaktiviert",
                        "Ohne Row-Level-Security können anon/authenticated-Rollen alle Zeilen lesen/schreiben, " +
                            "soweit die GRANTs das nicht abfangen. ($policyCount Policies vorhanden — irrelevant solange RLS aus ist.)",
                    )
                    off++
                }
                policyCount == 0 -> {
                    findings += Finding(
                        CheckStatus.YELLOW,
                        "Tabelle 'public.$table': RLS aktiv, aber 0 Policies",
                        "Tabelle ist effektiv komplett gesperrt (kein Zugriff für anon/authenticated). Wenn Zugriff vorgesehen war, fehlen Policies.",
                    )
                    lockedOut++
                }
                else -> {
                    findings += Finding(
                        CheckStatus.GREEN,
                        "Tabelle 'public.$table': RLS aktiv mit $policyCount Policy/Policies",
                        "Strukturell in Ordnung — die Policy-Logik selbst wird von permissive-policies geprüft.",
                    )
                    ok++
                }
            }
        }

        val summary = "${rows.size} Tabelle(n): $ok mit RLS+Policies, $lockedOut mit RLS ohne Policy, $off ohne RLS."
        return resultOf(findings, summary, start)
    }
}

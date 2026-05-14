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

@CheckId(name = "permissive-policies")
class PermissivePoliciesCheck(
    private val config: SupabaseConfig,
) : SecurityCheck {
    override val name = "Permissive RLS-Policies"
    override val description =
        "Liest pg_policies direkt via JDBC (read-only, SSL) und sucht typische Risiken: USING (true) bzw. " +
            "WITH CHECK (true) auf anon/authenticated, asymmetrische SELECT-vs-UPDATE-Policies, fehlende " +
            "WITH CHECK bei INSERT/UPDATE. Es werden KEINE Functions im Zielsystem angelegt."
    override val category = "Supabase / RLS"

    private data class Policy(
        val tableName: String,
        val policyName: String,
        val cmd: String,
        val roles: List<String>,
        val qual: String?,
        val withCheck: String?,
    )

    override fun run(): CheckResult {
        val start = Instant.now()
        if (!config.hasDbAccess) {
            return skipped(
                "DB-Zugang fehlt. Setze SUPABASE_DB_PASSWORD (Env) bzw. -Dsupabase.db.password=... und " +
                    "optional db.host in den properties.",
                start,
            )
        }

        val policies = try {
            PostgresQueryClient(config).use { client ->
                client.query(
                    """
                    SELECT tablename, policyname, cmd, roles, qual, with_check
                    FROM pg_policies
                    WHERE schemaname = 'public'
                    ORDER BY tablename, policyname
                    """.trimIndent(),
                ) { rs ->
                    val rolesArray = rs.getArray("roles")
                    val rolesList = if (rolesArray != null) {
                        (rolesArray.array as? Array<*>)?.mapNotNull { it?.toString() } ?: emptyList()
                    } else emptyList()
                    Policy(
                        tableName = rs.getString("tablename"),
                        policyName = rs.getString("policyname"),
                        cmd = (rs.getString("cmd") ?: "").uppercase(),
                        roles = rolesList,
                        qual = rs.getString("qual")?.trim(),
                        withCheck = rs.getString("with_check")?.trim(),
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

        if (policies.isEmpty()) {
            return resultOf(
                findings = listOf(
                    Finding(
                        CheckStatus.YELLOW,
                        "Keine RLS-Policies in public",
                        "Es wurden überhaupt keine Policies gefunden. Wenn Tabellen RLS aktiv haben, sind sie geschlossen.",
                    ),
                ),
                summary = "0 Policies.",
                start = start,
            )
        }

        val findings = mutableListOf<Finding>()
        for (p in policies) {
            val rolesStr = if (p.roles.isEmpty()) "PUBLIC" else p.roles.joinToString(",")
            val hitsAnon = p.roles.isEmpty() || "anon" in p.roles || "public" in p.roles.map { it.lowercase() }
            val hitsAuth = "authenticated" in p.roles
            val qualIsTrue = p.qual == "true"
            val checkIsTrue = p.withCheck == "true"

            when {
                qualIsTrue && hitsAnon && p.cmd in listOf("SELECT", "ALL") -> findings += Finding(
                    CheckStatus.RED,
                    "Policy '${p.policyName}' auf '${p.tableName}': anonymer Read-All",
                    "cmd=${p.cmd}, roles=$rolesStr, USING=true. Jeder anonyme Client liest alle Zeilen.",
                )
                qualIsTrue && hitsAuth && p.cmd in listOf("SELECT", "ALL") -> findings += Finding(
                    CheckStatus.YELLOW,
                    "Policy '${p.policyName}' auf '${p.tableName}': authenticated Read-All",
                    "cmd=${p.cmd}, roles=$rolesStr, USING=true. Jeder eingeloggte User sieht alle Zeilen — meist nicht gewollt.",
                )
                qualIsTrue && p.cmd in listOf("UPDATE", "DELETE", "ALL") -> findings += Finding(
                    CheckStatus.RED,
                    "Policy '${p.policyName}' auf '${p.tableName}': USING=true für ${p.cmd}",
                    "Beliebige Rolle ($rolesStr) darf ${p.cmd} auf allen Zeilen ausführen.",
                )
                checkIsTrue && p.cmd in listOf("INSERT", "UPDATE", "ALL") -> findings += Finding(
                    CheckStatus.RED,
                    "Policy '${p.policyName}' auf '${p.tableName}': WITH CHECK=true für ${p.cmd}",
                    "Keine Validierung der zu schreibenden Daten — beliebige Werte gehen durch.",
                )
                p.cmd == "UPDATE" && p.withCheck.isNullOrBlank() -> findings += Finding(
                    CheckStatus.YELLOW,
                    "Policy '${p.policyName}' auf '${p.tableName}': UPDATE ohne WITH CHECK",
                    "Klassisches Anti-Pattern: User darf eigene Zeile updaten, kann dabei aber den Owner-FK auf eine andere User-ID setzen.",
                )
                else -> findings += Finding(
                    CheckStatus.GREEN,
                    "Policy '${p.policyName}' auf '${p.tableName}' (${p.cmd}, roles=$rolesStr)",
                    "USING=${p.qual?.take(120) ?: "-"}, WITH CHECK=${p.withCheck?.take(120) ?: "-"}",
                )
            }
        }

        val red = findings.count { it.severity == CheckStatus.RED }
        val yellow = findings.count { it.severity == CheckStatus.YELLOW }
        val green = findings.count { it.severity == CheckStatus.GREEN }
        val tableCount = policies.map { it.tableName }.distinct().size
        val summary = "${policies.size} Policies in $tableCount Tabellen: $green OK, $yellow Warnung(en), $red kritisch."
        return resultOf(findings, summary, start)
    }
}

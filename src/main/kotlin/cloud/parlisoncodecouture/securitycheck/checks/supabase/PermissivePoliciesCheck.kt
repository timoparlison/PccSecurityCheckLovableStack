package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.Finding
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.core.resultOf
import cloud.parlisoncodecouture.securitycheck.core.skipped
import cloud.parlisoncodecouture.securitycheck.db.CatalogAccess
import cloud.parlisoncodecouture.securitycheck.db.CatalogQuery
import java.time.Instant

@CheckId(name = "permissive-policies")
class PermissivePoliciesCheck(
    private val config: SupabaseConfig,
    private val catalog: CatalogAccess,
) : SecurityCheck {
    override val name = "Permissive RLS-Policies"
    override val description =
        "Liest pg_policies (read-only) und sucht typische Risiken: USING (true) bzw. " +
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
        val source = catalog.sourceOrNull ?: return skipped(catalog.reason ?: "Kein Katalogzugang.", start)

        val policies = try {
            source.query(CatalogQuery.POLICIES).map { row ->
                Policy(
                    tableName = row.string("tablename") ?: "?",
                    policyName = row.string("policyname") ?: "?",
                    cmd = (row.string("cmd") ?: "").uppercase(),
                    roles = row.textArray("roles"),
                    qual = row.string("qual")?.trim(),
                    withCheck = row.string("with_check")?.trim(),
                )
            }
        } catch (e: Exception) {
            return resultOf(
                findings = listOf(
                    Finding(
                        CheckStatus.ERROR,
                        "Katalog-Query fehlgeschlagen",
                        "Quelle: ${source.provenance}. Fehler: ${e.message ?: e::class.simpleName}",
                    ),
                ),
                summary = "Katalogdaten nicht lesbar.",
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

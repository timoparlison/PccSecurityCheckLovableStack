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
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant

@CheckId(name = "permissive-policies")
class PermissivePoliciesCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    private val httpClient: SupabaseHttpClient = SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "Permissive RLS-Policies"
    override val description =
        "Ruft public.security_check_policies() per RPC (service_role) auf und sucht typische Risiken: " +
            "USING (true)/WITH CHECK (true) auf anon/authenticated, asymmetrische SELECT-vs-UPDATE-Policies, " +
            "fehlende WITH CHECK bei INSERT/UPDATE."
    override val category = "Supabase / RLS"

    private val json = Json { ignoreUnknownKeys = true }

    override fun run(): CheckResult {
        val start = Instant.now()
        val response = runCatching {
            httpClient.postJsonWithKey("/rest/v1/rpc/security_check_policies", config.serviceRoleKey, "{}")
        }.getOrElse {
            return resultOf(
                findings = listOf(
                    Finding(
                        CheckStatus.ERROR,
                        "RPC nicht erreichbar",
                        "Aufruf der Helper-Function fehlgeschlagen: ${it.message ?: it::class.simpleName}",
                    ),
                ),
                summary = "Aufruf fehlgeschlagen.",
                start = start,
            )
        }

        if (response.statusCode == 404 || (response.statusCode == 400 && response.body.contains("Could not find the function"))) {
            return skipped(
                "Helper-Funktion 'public.security_check_policies()' nicht installiert. " +
                    "Führe einmalig sql/setup.sql in deinem Supabase-Projekt aus.",
                start,
            )
        }
        if (!response.isSuccess) {
            return resultOf(
                findings = listOf(
                    Finding(
                        CheckStatus.ERROR,
                        "Unerwartete RPC-Antwort (HTTP ${response.statusCode})",
                        "POST /rest/v1/rpc/security_check_policies antwortete weder mit Erfolg noch klarem 404.",
                        evidence = response.body.take(400),
                    ),
                ),
                summary = "RPC fehlgeschlagen (HTTP ${response.statusCode}).",
                start = start,
            )
        }

        val rows = runCatching { json.parseToJsonElement(response.body).jsonArray }.getOrElse {
            return resultOf(
                findings = listOf(Finding(CheckStatus.ERROR, "Antwort ist kein JSON-Array", "Body: ${response.body.take(200)}")),
                summary = "Antwort nicht parsebar.",
                start = start,
            )
        }

        if (rows.isEmpty()) {
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
        val policiesByTable = rows.mapNotNull { it as? JsonObject }.groupBy {
            it["table_name"]?.jsonPrimitive?.content ?: "<unknown>"
        }

        for ((table, policies) in policiesByTable) {
            for (p in policies) {
                val policyName = p["policy_name"]?.jsonPrimitive?.contentOrNull ?: "?"
                val cmd = (p["cmd"]?.jsonPrimitive?.contentOrNull ?: "?").uppercase()
                val rolesNode = p["roles"]
                val roles = when (rolesNode) {
                    is JsonArray -> rolesNode.mapNotNull { it.jsonPrimitive.contentOrNull }
                    else -> emptyList()
                }
                val qual = p["qual"]?.jsonPrimitive?.contentOrNull?.trim()
                val withCheck = p["with_check"]?.jsonPrimitive?.contentOrNull?.trim()
                val rolesStr = if (roles.isEmpty()) "PUBLIC" else roles.joinToString(",")

                val hitsAnon = roles.isEmpty() || "anon" in roles || "PUBLIC" in roles.map { it.uppercase() } || "public" in roles
                val hitsAuth = "authenticated" in roles

                val qualIsTrue = qual == "true"
                val checkIsTrue = withCheck == "true"

                when {
                    qualIsTrue && hitsAnon && cmd in listOf("SELECT", "ALL") -> findings += Finding(
                        CheckStatus.RED,
                        "Policy '$policyName' auf '$table': anonymer Read-All",
                        "cmd=$cmd, roles=$rolesStr, USING=true. Jeder anonyme Client liest alle Zeilen.",
                    )
                    qualIsTrue && hitsAuth && cmd in listOf("SELECT", "ALL") -> findings += Finding(
                        CheckStatus.YELLOW,
                        "Policy '$policyName' auf '$table': authenticated Read-All",
                        "cmd=$cmd, roles=$rolesStr, USING=true. Jeder eingeloggte User sieht alle Zeilen — meist nicht gewollt.",
                    )
                    qualIsTrue && cmd in listOf("UPDATE", "DELETE", "ALL") -> findings += Finding(
                        CheckStatus.RED,
                        "Policy '$policyName' auf '$table': USING=true für $cmd",
                        "Beliebige Rolle ($rolesStr) darf $cmd auf allen Zeilen ausführen.",
                    )
                    checkIsTrue && cmd in listOf("INSERT", "UPDATE", "ALL") -> findings += Finding(
                        CheckStatus.RED,
                        "Policy '$policyName' auf '$table': WITH CHECK=true für $cmd",
                        "Keine Validierung der zu schreibenden Daten — beliebige Werte gehen durch.",
                    )
                    cmd == "UPDATE" && withCheck.isNullOrBlank() -> findings += Finding(
                        CheckStatus.YELLOW,
                        "Policy '$policyName' auf '$table': UPDATE ohne WITH CHECK",
                        "Klassisches Anti-Pattern: User darf eigene Zeile updaten, aber kann beim Update den Owner-FK auf eine andere User-ID setzen.",
                    )
                    else -> findings += Finding(
                        CheckStatus.GREEN,
                        "Policy '$policyName' auf '$table' ($cmd, roles=$rolesStr)",
                        "USING=${qual?.take(120) ?: "-"}, WITH CHECK=${withCheck?.take(120) ?: "-"}",
                    )
                }
            }
        }

        val red = findings.count { it.severity == CheckStatus.RED }
        val yellow = findings.count { it.severity == CheckStatus.YELLOW }
        val green = findings.count { it.severity == CheckStatus.GREEN }
        val summary = "${rows.size} Policies in ${policiesByTable.size} Tabellen: $green OK, $yellow Warnung(en), $red kritisch."
        return resultOf(findings, summary, start)
    }
}

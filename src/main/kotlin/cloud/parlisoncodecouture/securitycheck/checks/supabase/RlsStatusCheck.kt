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
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant

@CheckId(name = "rls-status")
class RlsStatusCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    private val httpClient: SupabaseHttpClient = SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "RLS-Status pro Tabelle (public-Schema)"
    override val description =
        "Ruft public.security_check_rls_status() per RPC (service_role) auf und prüft für jede " +
            "Tabelle in 'public', ob Row-Level-Security aktiviert ist und wie viele Policies anliegen. " +
            "Erfordert einmalige Installation des Helpers aus sql/setup.sql."
    override val category = "Supabase / RLS"

    private val json = Json { ignoreUnknownKeys = true }

    override fun run(): CheckResult {
        val start = Instant.now()
        val response = runCatching {
            httpClient.postJsonWithKey("/rest/v1/rpc/security_check_rls_status", config.serviceRoleKey, "{}")
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
                "Helper-Funktion 'public.security_check_rls_status()' nicht installiert. " +
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
                        "POST /rest/v1/rpc/security_check_rls_status antwortete weder mit Erfolg noch klarem 404.",
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

        val findings = mutableListOf<Finding>()
        var off = 0; var lockedOut = 0; var ok = 0
        for (row in rows) {
            val obj = (row as? JsonObject) ?: continue
            val table = obj["table_name"]?.jsonPrimitive?.content ?: continue
            val rlsEnabled = obj["rls_enabled"]?.jsonPrimitive?.booleanOrNull ?: false
            val policyCount = obj["policy_count"]?.jsonPrimitive?.intOrNull ?: 0
            when {
                !rlsEnabled -> {
                    findings += Finding(
                        CheckStatus.RED,
                        "Tabelle 'public.$table': RLS deaktiviert",
                        "Ohne Row-Level-Security können anon- und authenticated-Rollen alle Zeilen lesen/schreiben, " +
                            "sofern die GRANTs das nicht abfangen. Tabelle hat $policyCount Policies (irrelevant solange RLS aus ist).",
                    )
                    off++
                }
                policyCount == 0 -> {
                    findings += Finding(
                        CheckStatus.YELLOW,
                        "Tabelle 'public.$table': RLS aktiv, aber 0 Policies",
                        "Mit aktivem RLS und ohne Policies ist die Tabelle effektiv komplett gesperrt (kein Zugriff für " +
                            "anon/authenticated). Falls gewollt: OK. Falls Zugriff vorgesehen war: Policies fehlen.",
                    )
                    lockedOut++
                }
                else -> {
                    findings += Finding(
                        CheckStatus.GREEN,
                        "Tabelle 'public.$table': RLS aktiv mit $policyCount Policy/Policies",
                        "Strukturell in Ordnung — die Policy-Logik selbst wird vom permissive-policies-Check geprüft.",
                    )
                    ok++
                }
            }
        }

        if (findings.isEmpty()) {
            return resultOf(
                findings = listOf(Finding(CheckStatus.GREEN, "Keine Tabellen in public-Schema", "Nichts zu prüfen.")),
                summary = "0 Tabellen in public.",
                start = start,
            )
        }

        val summary = "${rows.size} Tabelle(n): $ok mit RLS+Policies, $lockedOut mit RLS ohne Policy, $off ohne RLS."
        return resultOf(findings, summary, start)
    }
}

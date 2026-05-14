package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.Finding
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.core.resultOf
import cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant

@CheckId(name = "auth-settings")
class AuthSettingsCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    private val httpClient: SupabaseHttpClient = SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "Auth-Settings Audit"
    override val description =
        "Liest /auth/v1/settings (anon) und bewertet typische Risiken: offene Signups ohne Mail-Verification, " +
            "Auto-Confirm aktiv, sehr permissive OAuth-Provider-Konfiguration."
    override val category = "Supabase / Auth"

    private val json = Json { ignoreUnknownKeys = true }

    override fun run(): CheckResult {
        val start = Instant.now()
        val response = runCatching {
            httpClient.getWithKey("/auth/v1/settings", config.anonKey)
        }.getOrElse {
            return resultOf(
                findings = listOf(Finding(CheckStatus.ERROR, "Auth-Settings nicht erreichbar", it.message ?: it::class.simpleName!!)),
                summary = "Aufruf fehlgeschlagen.",
                start = start,
            )
        }

        if (!response.isSuccess) {
            return resultOf(
                findings = listOf(
                    Finding(
                        CheckStatus.YELLOW,
                        "Auth-Settings nicht abrufbar (HTTP ${response.statusCode})",
                        "GET /auth/v1/settings lieferte keinen Erfolg.",
                        evidence = response.body.take(400),
                    ),
                ),
                summary = "Settings-Endpoint fehlgeschlagen (HTTP ${response.statusCode}).",
                start = start,
            )
        }

        val settings = runCatching { json.parseToJsonElement(response.body).jsonObject }.getOrElse {
            return resultOf(
                findings = listOf(Finding(CheckStatus.ERROR, "Antwort ist kein JSON-Object", response.body.take(200))),
                summary = "Antwort nicht parsebar.",
                start = start,
            )
        }

        val findings = mutableListOf<Finding>()
        val disableSignup = settings["disable_signup"]?.jsonPrimitive?.booleanOrNull ?: false
        val mailerAutoconfirm = settings["mailer_autoconfirm"]?.jsonPrimitive?.booleanOrNull ?: false
        val phoneAutoconfirm = settings["phone_autoconfirm"]?.jsonPrimitive?.booleanOrNull ?: false

        when {
            !disableSignup && mailerAutoconfirm -> findings += Finding(
                CheckStatus.RED,
                "Offene Signups + Mail-Auto-Confirm aktiv",
                "Jeder kann ohne Email-Verifikation Accounts anlegen — bedeutet authenticated-Rollen-Zugriff " +
                    "ohne nachweisbar gültige Email. Ein massiver Hebel gegen 'authenticated'-RLS-Policies.",
            )
            !disableSignup && !mailerAutoconfirm -> findings += Finding(
                CheckStatus.GREEN,
                "Offene Signups, aber Mail-Verifikation erforderlich",
                "Standardmäßiger Supabase-Default. OK.",
            )
            disableSignup -> findings += Finding(
                CheckStatus.GREEN,
                "Signups sind deaktiviert (disable_signup=true)",
                "Account-Erstellung über die public API ist abgeschaltet. Nur via service_role oder Invite möglich.",
            )
        }

        if (phoneAutoconfirm) {
            findings += Finding(
                CheckStatus.YELLOW,
                "phone_autoconfirm=true",
                "SMS-OTP-Verifikation wird übersprungen — falls SMS-Login genutzt wird, ist die " +
                    "Telefonnummer nicht nachweisbar gültig.",
            )
        }

        val external = settings["external"] as? JsonObject
        if (external != null) {
            val enabledProviders = external.entries
                .filter { (_, v) -> (v as? JsonObject)?.get("enabled")?.jsonPrimitive?.booleanOrNull == true ||
                    (v?.jsonPrimitive?.booleanOrNull == true) }
                .map { it.key }
            if (enabledProviders.isNotEmpty()) {
                findings += Finding(
                    CheckStatus.GREEN,
                    "OAuth-Provider aktiv: ${enabledProviders.joinToString(", ")}",
                    "Jede Konfiguration sollte ihre Redirect-URLs / Allowed-Hosts im Provider-Dashboard pflegen.",
                )
            }
        }

        val summary = buildString {
            append("disable_signup=$disableSignup, mailer_autoconfirm=$mailerAutoconfirm")
            if (phoneAutoconfirm) append(", phone_autoconfirm=true")
        }
        return resultOf(findings, summary, start)
    }
}

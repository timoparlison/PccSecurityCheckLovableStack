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
import kotlinx.serialization.json.intOrNull
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
            "Auto-Confirm aktiv, sehr permissive OAuth-Provider-Konfiguration, schwache Passwort-" +
            "Mindestlänge (< 8), fehlende MFA-Aktivierung. Hinweis: Supabase exponiert die Passwort-/MFA-" +
            "Felder erst ab bestimmten GoTrue-Versionen — fehlende Felder werden informativ behandelt."
    override val category = "Supabase / Auth"

    private companion object {
        const val MIN_PASSWORD_LENGTH = 8
    }

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

        val pwMin = settings["password_min_length"]?.jsonPrimitive?.intOrNull
        when {
            pwMin == null -> findings += Finding(
                CheckStatus.YELLOW,
                "Passwort-Mindestlänge nicht ausgelesen",
                "Das Feld 'password_min_length' fehlt in /auth/v1/settings. Entweder ältere GoTrue-Version " +
                    "oder bewusst nicht exponiert. Im Supabase-Dashboard prüfen, dass mindestens 8 Zeichen " +
                    "erzwungen werden.",
            )
            pwMin < MIN_PASSWORD_LENGTH -> findings += Finding(
                CheckStatus.YELLOW,
                "Passwort-Mindestlänge zu kurz: $pwMin",
                "Mindestlänge $pwMin Zeichen ist unterhalb des allgemein empfohlenen Minimums von " +
                    "$MIN_PASSWORD_LENGTH (BSI/NIST). Im Dashboard erhöhen.",
            )
            else -> findings += Finding(
                CheckStatus.GREEN,
                "Passwort-Mindestlänge: $pwMin",
                "Mindestens $MIN_PASSWORD_LENGTH wird empfohlen — erfüllt.",
            )
        }

        // MFA wird in Supabase üblicherweise als Feature-Flag exponiert.
        // Mögliche Feldnamen je nach Version: mfa_enabled, mfa.totp.enroll_enabled, …
        val mfaEnabled = settings["mfa_enabled"]?.jsonPrimitive?.booleanOrNull
            ?: (settings["mfa"] as? JsonObject)?.let { mfa ->
                val totp = (mfa["totp"] as? JsonObject)?.get("enroll_enabled")?.jsonPrimitive?.booleanOrNull
                val webauthn = (mfa["web_authn"] as? JsonObject)?.get("enroll_enabled")?.jsonPrimitive?.booleanOrNull
                listOfNotNull(totp, webauthn).any { it }.takeIf { totp != null || webauthn != null }
            }
        when (mfaEnabled) {
            true -> findings += Finding(
                CheckStatus.GREEN,
                "MFA-Enrollment aktiviert",
                "User können einen zweiten Faktor aktivieren. Anwendungslogik sollte für sensible Aktionen " +
                    "(Account-Settings, Payment) MFA erzwingen.",
            )
            false -> findings += Finding(
                CheckStatus.YELLOW,
                "MFA-Enrollment ist deaktiviert",
                "User können keinen zweiten Faktor hinzufügen. Bei Accounts mit Admin-Rollen erhebliches " +
                    "Risiko bei Credential-Stuffing.",
            )
            null -> findings += Finding(
                CheckStatus.YELLOW,
                "MFA-Status nicht auslesbar",
                "Weder 'mfa_enabled' noch 'mfa.totp.enroll_enabled' in /auth/v1/settings vorhanden. Im " +
                    "Supabase-Dashboard unter Authentication → Multi-Factor manuell prüfen.",
            )
        }

        val summary = buildString {
            append("disable_signup=$disableSignup, mailer_autoconfirm=$mailerAutoconfirm")
            if (phoneAutoconfirm) append(", phone_autoconfirm=true")
            if (pwMin != null) append(", password_min_length=$pwMin")
            if (mfaEnabled != null) append(", mfa=$mfaEnabled")
        }
        return resultOf(findings, summary, start)
    }
}

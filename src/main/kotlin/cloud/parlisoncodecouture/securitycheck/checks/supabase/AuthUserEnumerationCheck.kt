package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.Finding
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.core.resultOf
import cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient
import io.github.oshai.kotlinlogging.KotlinLogging
import java.time.Instant
import java.util.UUID

private val log = KotlinLogging.logger {}

@CheckId(name = "auth-user-enumeration")
class AuthUserEnumerationCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    private val httpClient: SupabaseHttpClient = SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "User-Enumeration über /auth/v1/*"
    override val description =
        "Sendet je einen Password-Recovery- und einen OTP-Magic-Link-Request mit einer zufällig generierten " +
            "Mail auf der reservierten .invalid-TLD (RFC 2606 — diese Domain existiert garantiert nicht, also " +
            "keine echten Mails). Erwartet eine generische 2xx-Antwort ohne Hinweis, ob die Mail registriert " +
            "ist. Antworten wie 'user not found', HTTP 404 oder explizite Existenz-Fehler wären eine " +
            "klassische User-Enumeration-Lücke (BSI APP.3.1, OWASP A07)."
    override val category = "Supabase / Auth"

    // Phrasen, die Existenz-Information leaken. Bewusst klein gehalten und nur Substring-Match.
    private val leakPhrases = listOf(
        "user not found",
        "no user found",
        "email not found",
        "user does not exist",
        "user_not_found",
        "not registered",
        "unknown email",
        "user with this email",
        "no such user",
    )

    override fun run(): CheckResult {
        val start = Instant.now()
        val findings = mutableListOf<Finding>()

        val probeMail = "pcc-securitycheck-${UUID.randomUUID().toString().take(8)}@nonexistent.invalid"
        log.info { "Enumeration-Probe mit nicht-existenter Mail '$probeMail'" }

        probeEndpoint("/auth/v1/recover", "Password-Recovery", probeMail, findings)
        probeEndpoint("/auth/v1/otp", "Magic-Link/OTP", probeMail, findings)

        if (findings.none { it.severity != CheckStatus.GREEN }) {
            findings += Finding(
                CheckStatus.GREEN,
                "Keine Enumeration-Signale erkannt",
                "Recover- und OTP-Endpoint antworten auf nicht-existente Mails ohne erkennbaren Existenz-Hinweis.",
            )
        }

        return resultOf(findings, "2 Auth-Endpoints auf Enumeration-Leaks geprüft.", start)
    }

    private fun probeEndpoint(path: String, label: String, email: String, findings: MutableList<Finding>) {
        val body = """{"email":"$email"}"""
        val resp = runCatching { httpClient.postJsonWithKey(path, config.anonKey, body) }.getOrNull()
        if (resp == null) {
            findings += Finding(
                CheckStatus.YELLOW,
                "$label-Probe fehlgeschlagen",
                "POST $path lieferte eine Ausnahme.",
            )
            return
        }

        log.info { "  $label → HTTP ${resp.statusCode}" }
        val bodyLower = resp.body.lowercase()
        val leakHit = leakPhrases.firstOrNull { bodyLower.contains(it) }

        when {
            leakHit != null -> findings += Finding(
                CheckStatus.RED,
                "$label leakt Existenz-Info ('$leakHit')",
                "POST $path mit nicht existierender Mail liefert eine Antwort, die explizit angibt, dass " +
                    "der User nicht existiert. Damit kann ein Angreifer gültige Mail-Adressen enumerieren.",
                evidence = resp.body.take(400),
            )
            resp.statusCode == 404 -> findings += Finding(
                CheckStatus.RED,
                "$label: HTTP 404 auf nicht-existente Mail",
                "Statuscode 404 ist ein eindeutiges Enumeration-Signal — registrierte Mails liefern 2xx, " +
                    "unbekannte 404.",
                evidence = resp.body.take(400),
            )
            resp.statusCode in 200..299 -> findings += Finding(
                CheckStatus.GREEN,
                "$label: generische 2xx-Antwort (HTTP ${resp.statusCode})",
                "Keine Existenz-Information im Response-Body erkannt.",
            )
            resp.statusCode == 429 -> findings += Finding(
                CheckStatus.YELLOW,
                "$label: Rate-Limit aktiv (HTTP 429)",
                "Probe vom Rate-Limit blockiert — Enumeration konnte nicht abschließend bewertet werden. " +
                    "Einerseits ist Rate-Limiting gut (begrenzt Brute-Force), andererseits sollte ein " +
                    "manueller Re-Test stattfinden, sobald das Limit zurückgesetzt ist.",
            )
            resp.statusCode == 422 -> findings += Finding(
                CheckStatus.GREEN,
                "$label: 422 Unprocessable (Format-Filter)",
                "GoTrue weist .invalid-Mails häufig mit 422 ab — daraus lässt sich keine Existenz ableiten.",
            )
            else -> findings += Finding(
                CheckStatus.YELLOW,
                "$label: unerwarteter Status HTTP ${resp.statusCode}",
                "Weder generischer 2xx noch klares Enumeration-Signal. Manuell prüfen, ob der Body " +
                    "Existenz-Hinweise enthält.",
                evidence = resp.body.take(400),
            )
        }
    }
}

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
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private val log = KotlinLogging.logger {}

@CheckId(name = "jwt-hardening")
class JwtHardeningCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    private val httpClient: SupabaseHttpClient = SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "JWT-Hardening (alg=none + schwache Secrets)"
    override val description =
        "Schmiedet JWTs mit role='service_role' und probiert sie gegen /auth/v1/admin/users: " +
            "(1) alg=none (unsignierter Token darf NIE akzeptiert werden), " +
            "(2) HS256 mit bekannten Default-/Schwach-Secrets (Supabase local-dev Default, 'secret', " +
            "'supabase', generische 32-char Platzhalter). " +
            "Falls eine Variante 2xx zurückliefert, ist der JWT-Secret bekannt oder die Validierung " +
            "kaputt — das entspricht effektivem service_role-Zugang für jeden externen Aufrufer."
    override val category = "Supabase / Auth"

    private val b64 = Base64.getUrlEncoder().withoutPadding()

    // Bekannte schwache / Default-Secrets. Supabase-CLI verwendet lokal den ersten Eintrag —
    // wenn der je nach Copy-Paste in Prod landet, ist der Cluster trivial übernehmbar.
    private val weakSecrets = listOf(
        "your-super-secret-jwt-token-with-at-least-32-characters-long",
        "super-secret-jwt-token-with-at-least-32-characters-long",
        "supabase-jwt-secret",
        "supabase",
        "secret",
        "changeme",
        "0123456789abcdef0123456789abcdef",
    )

    override fun run(): CheckResult {
        val start = Instant.now()
        val findings = mutableListOf<Finding>()

        val now = Instant.now().epochSecond
        val payload = """{"role":"service_role","iss":"supabase","ref":"${config.projectRef ?: "x"}","iat":$now,"exp":${now + 3600}}"""
        val payloadB64 = b64.encodeToString(payload.toByteArray(Charsets.UTF_8))

        // 1) alg=none — unsignierter Token
        val noneHeader = b64.encodeToString("""{"alg":"none","typ":"JWT"}""".toByteArray(Charsets.UTF_8))
        val noneToken = "$noneHeader.$payloadB64."
        probeForgedToken("alg=none (unsigniert)", noneToken, findings, weakSecret = false)

        // 2) HS256 mit Schwach-Secrets
        val h256 = b64.encodeToString("""{"alg":"HS256","typ":"JWT"}""".toByteArray(Charsets.UTF_8))
        for (secret in weakSecrets) {
            val signingInput = "$h256.$payloadB64"
            val sig = hmacSha256(signingInput, secret)
            val token = "$signingInput.${b64.encodeToString(sig)}"
            probeForgedToken("HS256 mit Secret='${secret.take(40)}${if (secret.length > 40) "…" else ""}'", token, findings, weakSecret = true)
        }

        if (findings.none { it.severity == CheckStatus.RED }) {
            findings += Finding(
                CheckStatus.GREEN,
                "JWT-Validierung lehnt alle geschmiedeten Token ab",
                "${weakSecrets.size + 1} Varianten geprüft (alg=none + ${weakSecrets.size} bekannte schwache Secrets). " +
                    "Keine wurde von /auth/v1/admin/users akzeptiert.",
            )
        }

        val summary = "${weakSecrets.size + 1} geschmiedete Token gegen /auth/v1/admin/users probiert."
        return resultOf(findings, summary, start)
    }

    private fun probeForgedToken(label: String, token: String, findings: MutableList<Finding>, weakSecret: Boolean) {
        val resp = runCatching {
            httpClient.getWithKey("/auth/v1/admin/users?per_page=1", token)
        }.getOrNull() ?: return

        log.info { "  jwt-probe '$label' → HTTP ${resp.statusCode}" }
        when {
            resp.statusCode in 200..299 -> {
                val cause = if (weakSecret) {
                    "Das Projekt verwendet eines der bekannten Default-/Schwach-Secrets — der JWT-Secret in den " +
                        "Supabase-Projekt-Settings muss SOFORT rotiert werden (und damit auch anon/service_role-Keys)."
                } else {
                    "Die JWT-Library akzeptiert unsignierte Token (klassischer alg=none-Bug). Gateway/GoTrue-Version prüfen."
                }
                findings += Finding(
                    CheckStatus.RED,
                    "Geschmiedeter service_role-Token akzeptiert: $label",
                    "GET /auth/v1/admin/users?per_page=1 lieferte HTTP ${resp.statusCode} mit einem von uns " +
                        "geschmiedeten service_role-Token. $cause",
                    evidence = resp.body.take(400),
                )
            }
            resp.statusCode in listOf(401, 403) -> { /* erwartet */ }
            else -> {
                // Inkonklusiv (z. B. 5xx) — als Warnung notieren, aber nicht rot
                findings += Finding(
                    CheckStatus.YELLOW,
                    "$label: unerwarteter Status HTTP ${resp.statusCode}",
                    "Weder klare Ablehnung (401/403) noch Erfolg. Body kurz prüfen.",
                    evidence = resp.body.take(200),
                )
            }
        }
    }

    private fun hmacSha256(data: String, secret: String): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // Mac.init verbietet leere Schlüssel — für echtes Probing reichen nicht-leere Secrets.
        mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
        return mac.doFinal(data.toByteArray(Charsets.UTF_8))
    }
}

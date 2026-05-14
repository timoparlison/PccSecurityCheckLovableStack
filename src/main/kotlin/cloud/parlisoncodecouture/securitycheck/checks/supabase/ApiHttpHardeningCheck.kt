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
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant

private val log = KotlinLogging.logger {}

@CheckId(name = "api-http-hardening")
class ApiHttpHardeningCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    @Suppress("UNUSED_PARAMETER") httpClient: SupabaseHttpClient = SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "API HTTP-Hardening (CORS & Security-Header)"
    override val description =
        "Probt /rest/v1/ und /auth/v1/* mit einem feindlichen Origin (https://evil.example.com) " +
            "via OPTIONS-Preflight und realem GET. Bewertet: " +
            "(1) CORS-Reflektion + Allow-Credentials (klassisches BSI/OWASP-A05-Pattern), " +
            "(2) Defense-in-Depth-Header: Strict-Transport-Security, X-Content-Type-Options, " +
            "Referrer-Policy. Supabase nutzt Bearer-Tokens statt Cookies, daher ist CORS-Reflektion " +
            "ohne Credentials eher Warnung — mit Credentials aber kritisch."
    override val category = "Supabase / HTTP-Hardening"

    private val javaClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(config.connectTimeoutSeconds))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build()

    private data class Probe(val label: String, val path: String)
    private val probes = listOf(
        Probe("REST root", "/rest/v1/"),
        Probe("Auth settings", "/auth/v1/settings"),
        Probe("Auth health", "/auth/v1/health"),
    )

    private val evilOrigin = "https://evil.example.com"

    override fun run(): CheckResult {
        val start = Instant.now()
        val findings = mutableListOf<Finding>()

        for (probe in probes) {
            log.info { "probing '${probe.label}' (${probe.path})" }

            val preflight = runCatching { sendOptions(probe.path) }.getOrNull()
            if (preflight != null) {
                checkCors("${probe.label} [OPTIONS]", preflight.headers().map(), findings)
            }

            val getResp = runCatching { sendGetWithOrigin(probe.path) }.getOrNull()
            if (getResp == null) {
                findings += Finding(
                    CheckStatus.YELLOW,
                    "${probe.label}: nicht erreichbar",
                    "Weder OPTIONS noch GET ${probe.path} lieferten eine Antwort.",
                )
                continue
            }
            val getHeaders = getResp.headers().map()
            checkCors("${probe.label} [GET]", getHeaders, findings)
            checkSecurityHeaders(probe.label, getHeaders, findings)
        }

        if (findings.none { it.severity != CheckStatus.GREEN }) {
            findings += Finding(
                CheckStatus.GREEN,
                "Keine Auffälligkeiten bei CORS/Security-Headern",
                "${probes.size} Endpoint(s) gegen Origin '$evilOrigin' geprüft.",
            )
        }

        val red = findings.count { it.severity == CheckStatus.RED }
        val yellow = findings.count { it.severity == CheckStatus.YELLOW }
        val summary = "${probes.size} Endpoint(s) geprüft: $red kritisch, $yellow Warnung(en)."
        return resultOf(findings, summary, start)
    }

    private fun sendOptions(path: String): HttpResponse<String> {
        val url = "${config.baseUrl}${if (path.startsWith("/")) path else "/$path"}"
        val req = HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(config.requestTimeoutSeconds))
            .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
            .header("Origin", evilOrigin)
            .header("Access-Control-Request-Method", "GET")
            .header("Access-Control-Request-Headers", "authorization,apikey,content-type")
            .build()
        return javaClient.send(req, HttpResponse.BodyHandlers.ofString())
    }

    private fun sendGetWithOrigin(path: String): HttpResponse<String> {
        val url = "${config.baseUrl}${if (path.startsWith("/")) path else "/$path"}"
        val req = HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(config.requestTimeoutSeconds))
            .header("Origin", evilOrigin)
            .header("apikey", config.anonKey)
            .header("Authorization", "Bearer ${config.anonKey}")
            .header("Accept", "application/json")
            .GET()
            .build()
        return javaClient.send(req, HttpResponse.BodyHandlers.ofString())
    }

    private fun headerCi(headers: Map<String, List<String>>, name: String): String? =
        headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value?.firstOrNull()

    private fun checkCors(label: String, headers: Map<String, List<String>>, findings: MutableList<Finding>) {
        val acao = headerCi(headers, "Access-Control-Allow-Origin")
        val acac = headerCi(headers, "Access-Control-Allow-Credentials")?.lowercase()

        when {
            acao == "*" && acac == "true" -> findings += Finding(
                CheckStatus.RED,
                "$label: Allow-Origin '*' + Allow-Credentials 'true'",
                "Diese Kombination ist von CORS-Spec verboten, wird aber von älteren Browsern teils akzeptiert. " +
                    "Resultat: jede fremde Origin könnte mit Credentials auf den Endpoint zugreifen.",
            )
            acao == evilOrigin && acac == "true" -> findings += Finding(
                CheckStatus.RED,
                "$label: reflektiert Origin + Allow-Credentials 'true'",
                "Allow-Origin spiegelt die gesendete Origin ($evilOrigin) zurück UND erlaubt Credentials. " +
                    "Jede beliebige Webseite kann eingeloggte Browser-Sessions zum Datenabgriff missbrauchen.",
            )
            acao == evilOrigin -> findings += Finding(
                CheckStatus.YELLOW,
                "$label: spiegelt beliebige Origin (ohne Credentials)",
                "Allow-Origin reflektiert die gesendete Origin ($evilOrigin). Da Supabase mit Bearer-Tokens " +
                    "arbeitet, ist das Risiko begrenzt — sollte aber bewusst sein und ggf. auf eine Allowlist " +
                    "im Gateway umgestellt werden.",
            )
            acao == "*" -> {
                // Standard für Supabase REST/Auth — kein Finding, das ist Design.
            }
            acao.isNullOrBlank() -> { /* kein CORS-Header → kein Browser-Zugriff möglich, OK */ }
        }
    }

    private fun checkSecurityHeaders(label: String, headers: Map<String, List<String>>, findings: MutableList<Finding>) {
        val hsts = headerCi(headers, "Strict-Transport-Security")
        val xcto = headerCi(headers, "X-Content-Type-Options")
        val ref = headerCi(headers, "Referrer-Policy")

        if (hsts.isNullOrBlank()) {
            findings += Finding(
                CheckStatus.YELLOW,
                "$label: HSTS fehlt",
                "Strict-Transport-Security nicht gesetzt — Downgrade-Angriffe auf HTTPS bleiben möglich. " +
                    "Empfehlung: 'max-age=31536000; includeSubDomains'.",
            )
        }
        if (xcto.isNullOrBlank()) {
            findings += Finding(
                CheckStatus.YELLOW,
                "$label: X-Content-Type-Options fehlt",
                "Ohne 'X-Content-Type-Options: nosniff' kann der Browser MIME-Typen erraten — relevant bei " +
                    "User-Uploads, die als JSON ausgeliefert werden.",
            )
        }
        if (ref.isNullOrBlank()) {
            findings += Finding(
                CheckStatus.YELLOW,
                "$label: Referrer-Policy fehlt",
                "Ohne Referrer-Policy lecken Anfrage-URLs (inkl. Query-Strings mit Tokens) im Referer-Header " +
                    "an Drittseiten.",
            )
        }
    }
}

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
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import java.net.URI
import java.time.Instant
import java.util.Base64

@CheckId(name = "frontend-service-role-leak")
class FrontendServiceRoleLeakCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    private val httpClient: SupabaseHttpClient = SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "Service-Role-Key-Leak im Frontend-Bundle"
    override val description =
        "Lädt die Frontend-URL, extrahiert alle JS-Bundles und Inline-Skripte, scannt nach JWTs " +
            "(Pattern eyJh…), dekodiert den Payload und meldet jeden Key mit role='service_role'. " +
            "Prüft nebenbei zentrale Security-Header auf der HTML-Response."
    override val category = "Frontend / Lovable"

    private val json = Json { ignoreUnknownKeys = true }
    private val jwtRegex = Regex("""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}""")
    private val scriptSrcRegex = Regex("""<script[^>]*\bsrc\s*=\s*["']([^"']+)["']""", RegexOption.IGNORE_CASE)
    private val inlineScriptRegex = Regex(
        """<script(?![^>]*\bsrc\s*=)[^>]*>([\s\S]*?)</script>""",
        RegexOption.IGNORE_CASE,
    )

    override fun run(): CheckResult {
        val start = Instant.now()
        val frontendUrl = config.frontendUrl
            ?: return skipped("frontend.url ist nicht gesetzt — Check übersprungen.", start)

        val htmlResponse = runCatching { httpClient.getAbsolute(frontendUrl) }.getOrElse {
            return resultOf(
                findings = listOf(Finding(CheckStatus.ERROR, "Frontend nicht erreichbar", "$frontendUrl: ${it.message ?: it::class.simpleName}")),
                summary = "Frontend-URL nicht erreichbar.",
                start = start,
            )
        }

        if (!htmlResponse.isSuccess) {
            return resultOf(
                findings = listOf(
                    Finding(
                        CheckStatus.YELLOW,
                        "Frontend antwortet mit HTTP ${htmlResponse.statusCode}",
                        "Konnte $frontendUrl nicht erfolgreich laden.",
                    ),
                ),
                summary = "Frontend nicht 2xx (HTTP ${htmlResponse.statusCode}).",
                start = start,
            )
        }

        val findings = mutableListOf<Finding>()
        checkSecurityHeaders(htmlResponse.headers, findings)

        val html = htmlResponse.body
        val scriptUrls = scriptSrcRegex.findAll(html).map { it.groupValues[1] }.toList()
        val inlineScripts = inlineScriptRegex.findAll(html).map { it.groupValues[1] }.toList()

        var serviceRoleHits = 0
        var anonHits = 0
        var otherJwts = 0

        // Inline scripts + HTML body itself (Vite often inlines env)
        scanText("inline html", html, findings) { stats -> serviceRoleHits += stats.first; anonHits += stats.second; otherJwts += stats.third }
        inlineScripts.forEachIndexed { idx, content ->
            scanText("inline-script[$idx]", content, findings) { stats -> serviceRoleHits += stats.first; anonHits += stats.second; otherJwts += stats.third }
        }

        for (src in scriptUrls.distinct()) {
            val absUrl = absolutize(frontendUrl, src)
            val res = runCatching { httpClient.getAbsolute(absUrl) }.getOrNull()
            if (res == null || !res.isSuccess) {
                findings += Finding(
                    CheckStatus.YELLOW,
                    "Script nicht ladbar: $absUrl",
                    "HTTP ${res?.statusCode ?: "n/a"} — Script konnte nicht gescannt werden.",
                )
                continue
            }
            scanText(absUrl, res.body, findings) { stats -> serviceRoleHits += stats.first; anonHits += stats.second; otherJwts += stats.third }
        }

        val summary = "${scriptUrls.size} externe + ${inlineScripts.size} inline Scripts gescannt. " +
            "Funde: $serviceRoleHits service_role, $anonHits anon, $otherJwts andere JWTs."
        return resultOf(findings, summary, start)
    }

    private fun scanText(
        sourceLabel: String,
        text: String,
        findings: MutableList<Finding>,
        onHit: (Triple<Int, Int, Int>) -> Unit,
    ) {
        var sr = 0; var an = 0; var ot = 0
        for (match in jwtRegex.findAll(text)) {
            val jwt = match.value
            val payload = decodePayload(jwt)
            val role = payload?.get("role")?.let { (it as? JsonPrimitive)?.contentOrNull }
            when (role) {
                "service_role" -> {
                    findings += Finding(
                        CheckStatus.RED,
                        "SERVICE-ROLE-Key gefunden in '$sourceLabel'",
                        "Im ausgelieferten Frontend-Bundle wurde ein JWT mit role='service_role' gefunden. " +
                            "Das bedeutet: jeder Besucher der Seite kann mit diesem Key die gesamte " +
                            "Datenbank lesen und schreiben (bypasst RLS komplett). Sofort rotieren!",
                        evidence = "JWT (gekürzt): ${jwt.take(40)}…${jwt.takeLast(20)}",
                    )
                    sr++
                }
                "anon" -> an++ // erwartet, keine Findings
                null -> ot++   // nicht decodebar / kein Supabase-Key
                else -> {
                    findings += Finding(
                        CheckStatus.YELLOW,
                        "Unbekannte Rolle '$role' im JWT in '$sourceLabel'",
                        "JWT mit role='$role' im Frontend gefunden. Sollte normalerweise nur 'anon' sein.",
                        evidence = "JWT (gekürzt): ${jwt.take(40)}…${jwt.takeLast(20)}",
                    )
                    ot++
                }
            }
        }
        onHit(Triple(sr, an, ot))
    }

    private fun checkSecurityHeaders(headers: Map<String, List<String>>, findings: MutableList<Finding>) {
        fun header(name: String) = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value?.firstOrNull()

        val hsts = header("Strict-Transport-Security")
        val csp = header("Content-Security-Policy")
        val xfo = header("X-Frame-Options")
        val xcto = header("X-Content-Type-Options")

        if (hsts.isNullOrBlank()) {
            findings += Finding(CheckStatus.YELLOW, "Header fehlt: Strict-Transport-Security",
                "HSTS sollte gesetzt sein, damit Browser HTTPS erzwingen (z. B. 'max-age=31536000; includeSubDomains').")
        }
        if (csp.isNullOrBlank()) {
            findings += Finding(CheckStatus.YELLOW, "Header fehlt: Content-Security-Policy",
                "Ohne CSP keine Mitigation gegen reflected/stored XSS via injected scripts.")
        }
        if (xfo.isNullOrBlank() && (csp == null || !csp.contains("frame-ancestors"))) {
            findings += Finding(CheckStatus.YELLOW, "Header fehlt: X-Frame-Options (oder CSP frame-ancestors)",
                "Clickjacking-Schutz fehlt — die Seite kann in beliebige iframes eingebettet werden.")
        }
        if (xcto.isNullOrBlank()) {
            findings += Finding(CheckStatus.YELLOW, "Header fehlt: X-Content-Type-Options: nosniff",
                "Verhindert MIME-Sniffing-Angriffe auf User-Uploads.")
        }
    }

    private fun decodePayload(jwt: String): JsonObject? {
        val parts = jwt.split(".")
        if (parts.size != 3) return null
        return runCatching {
            val padded = parts[1].let {
                val mod = it.length % 4
                if (mod == 0) it else it.padEnd(it.length + (4 - mod), '=')
            }
            val decoded = Base64.getUrlDecoder().decode(padded)
            json.parseToJsonElement(String(decoded)) as? JsonObject
        }.getOrNull()
    }

    private fun absolutize(baseUrl: String, src: String): String {
        if (src.startsWith("http://") || src.startsWith("https://")) return src
        val base = URI.create(baseUrl)
        if (src.startsWith("//")) return "${base.scheme}:$src"
        if (src.startsWith("/")) return "${base.scheme}://${base.authority}$src"
        // relative path
        val basePath = base.rawPath.substringBeforeLast('/', "")
        return "${base.scheme}://${base.authority}$basePath/$src"
    }
}

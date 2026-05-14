package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.Finding
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.longOrNull
import java.time.Duration
import java.time.Instant
import java.util.Base64

@CheckId(name = "config-sanity")
class ConfigSanityCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    private val httpClient: SupabaseHttpClient = SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "Supabase Konfiguration & Schlüssel-Plausibilität"
    override val description =
        "Prüft URL-Schema, JWT-Claims (role/iss/exp) für Anon- und Service-Role-Key " +
            "sowie die Erreichbarkeit der REST-API mit beiden Schlüsseln."
    override val category = "Supabase / Konfiguration"

    private val json = Json { ignoreUnknownKeys = true }

    override fun run(): CheckResult {
        val start = Instant.now()
        val findings = mutableListOf<Finding>()

        checkUrlScheme(findings)
        checkKeysDiffer(findings)
        checkJwt("Anon-Key", config.anonKey, expectedRole = "anon", findings)
        checkJwt("Service-Role-Key", config.serviceRoleKey, expectedRole = "service_role", findings)
        checkConnectivity("Anon-Key", config.anonKey, findings)
        checkConnectivity("Service-Role-Key", config.serviceRoleKey, findings)

        val status = CheckStatus.worstOf(findings.map { it.severity })
        return CheckResult(
            checkId = id,
            checkName = name,
            checkDescription = description,
            category = category,
            status = status,
            summary = buildSummary(findings),
            findings = findings,
            executedAt = start,
            durationMs = Duration.between(start, Instant.now()).toMillis(),
        )
    }

    private fun checkUrlScheme(findings: MutableList<Finding>) {
        when {
            config.url.startsWith("https://") -> findings += Finding(
                CheckStatus.GREEN,
                "URL nutzt HTTPS",
                "Die Supabase-URL beginnt mit https://.",
            )
            config.url.startsWith("http://") -> findings += Finding(
                CheckStatus.RED,
                "URL nutzt HTTP statt HTTPS",
                "Verkehr ist im Klartext lesbar. Verwende https://${config.url.removePrefix("http://")}.",
            )
            else -> findings += Finding(
                CheckStatus.RED,
                "URL hat kein gültiges Schema",
                "Erwartet: https://<project-ref>.supabase.co. Gefunden: ${config.url}",
            )
        }
    }

    private fun checkKeysDiffer(findings: MutableList<Finding>) {
        if (config.anonKey == config.serviceRoleKey) {
            findings += Finding(
                CheckStatus.RED,
                "Anon-Key und Service-Role-Key sind identisch",
                "Beide Konfigurationswerte enthalten denselben JWT — vermutlich wurde derselbe Key " +
                    "(sehr wahrscheinlich der Service-Role-Key) an beiden Stellen eingetragen. " +
                    "Im Frontend würde das die komplette Datenbank exponieren.",
            )
        }
    }

    private fun checkJwt(
        label: String,
        jwt: String,
        expectedRole: String,
        findings: MutableList<Finding>,
    ) {
        val payload = decodeJwtPayload(jwt)
        if (payload == null) {
            findings += Finding(
                CheckStatus.RED,
                "$label ist kein gültiger JWT",
                "Der Wert konnte nicht in einen JWT-Payload dekodiert werden. " +
                    "Prüfe, ob der Key vollständig kopiert wurde (drei mit '.' getrennte Segmente).",
            )
            return
        }

        val role = (payload["role"] as? JsonPrimitive)?.contentOrNull
        val iss = (payload["iss"] as? JsonPrimitive)?.contentOrNull
        val exp = (payload["exp"] as? JsonPrimitive)?.longOrNull
        val ref = (payload["ref"] as? JsonPrimitive)?.contentOrNull

        if (role == expectedRole) {
            findings += Finding(
                CheckStatus.GREEN,
                "$label hat Rolle '$expectedRole'",
                "JWT-Claims: role=$role, iss=${iss ?: "?"}, ref=${ref ?: "?"}.",
            )
        } else {
            findings += Finding(
                CheckStatus.RED,
                "$label hat unerwartete Rolle",
                "Erwartet role='$expectedRole', gefunden role='${role ?: "<keine>"}'. " +
                    "Möglicherweise sind Anon- und Service-Role-Key vertauscht.",
            )
        }

        if (iss != null && iss != "supabase") {
            findings += Finding(
                CheckStatus.YELLOW,
                "$label: ungewöhnlicher iss-Claim",
                "iss='$iss' — Supabase-Standard ist 'supabase'. Self-Hosting oder Drittanbieter?",
            )
        }

        if (ref != null && config.projectRef != null && ref != config.projectRef) {
            findings += Finding(
                CheckStatus.RED,
                "$label gehört zu einem anderen Projekt",
                "JWT-Claim ref='$ref', konfigurierte URL deutet aber auf projectRef='${config.projectRef}' hin.",
            )
        }

        if (exp != null) {
            val expiresAt = Instant.ofEpochSecond(exp)
            val now = Instant.now()
            val daysLeft = Duration.between(now, expiresAt).toDays()
            when {
                expiresAt.isBefore(now) -> findings += Finding(
                    CheckStatus.RED,
                    "$label ist abgelaufen",
                    "exp=$expiresAt liegt in der Vergangenheit. Der Key wird vom Server abgelehnt.",
                )
                daysLeft < 30 -> findings += Finding(
                    CheckStatus.YELLOW,
                    "$label läuft in $daysLeft Tagen ab",
                    "exp=$expiresAt — Rotation einplanen.",
                )
            }
        }
    }

    private fun checkConnectivity(label: String, key: String, findings: MutableList<Finding>) {
        // /auth/v1/settings statt /rest/v1/, weil PostgREST den Root-Endpoint für die
        // anon-Rolle oft bewusst sperrt (OpenAPI-Spec-Härtung) → würde 401 liefern,
        // obwohl der Key gültig ist. GoTrue-Settings validiert den apikey-Header
        // direkt und gibt 200 bei einem akzeptierten Key zurück.
        val authUrl = "${config.baseUrl}/auth/v1/settings"
        val result = runCatching { httpClient.getWithKey("/auth/v1/settings", key) }
        result.onFailure {
            findings += Finding(
                CheckStatus.RED,
                "$label: Supabase-API nicht erreichbar",
                "Fehler beim Aufruf von $authUrl: ${it.message ?: it::class.simpleName}",
            )
        }
        result.onSuccess { r ->
            when (r.statusCode) {
                in 200..299 -> findings += Finding(
                    CheckStatus.GREEN,
                    "$label: Supabase akzeptiert den Schlüssel (HTTP ${r.statusCode})",
                    "$authUrl antwortet erfolgreich — der Key wird vom GoTrue-Auth-Endpoint validiert.",
                )
                401, 403 -> findings += Finding(
                    CheckStatus.RED,
                    "$label: Authentifizierung abgelehnt (HTTP ${r.statusCode})",
                    "GoTrue ($authUrl) lehnt den Key ab — eventuell falsches Projekt, beschädigter Key oder abgelaufenes JWT.",
                    evidence = r.body.take(400),
                )
                else -> findings += Finding(
                    CheckStatus.YELLOW,
                    "$label: unerwartete Antwort (HTTP ${r.statusCode})",
                    "$authUrl antwortet weder mit Erfolg noch klarem Auth-Fehler. Eventuell GoTrue deaktiviert (Self-Hosting?).",
                    evidence = r.body.take(400),
                )
            }
        }
    }

    private fun decodeJwtPayload(jwt: String): JsonObject? {
        val parts = jwt.split(".")
        if (parts.size != 3) return null
        return runCatching {
            val decoded = Base64.getUrlDecoder().decode(parts[1].padBase64())
            json.parseToJsonElement(String(decoded)) as? JsonObject
        }.getOrNull()
    }

    private fun String.padBase64(): String {
        val mod = length % 4
        return if (mod == 0) this else padEnd(length + (4 - mod), '=')
    }

    private fun buildSummary(findings: List<Finding>): String {
        val red = findings.count { it.severity == CheckStatus.RED }
        val yellow = findings.count { it.severity == CheckStatus.YELLOW }
        val green = findings.count { it.severity == CheckStatus.GREEN }
        return "Konfiguration: $green OK, $yellow Warnung(en), $red kritisch."
    }
}

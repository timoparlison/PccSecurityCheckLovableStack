package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckId
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.Finding
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.time.Duration
import java.time.Instant

private val log = KotlinLogging.logger {}

@CheckId(name = "anon-read-exposure")
class AnonReadExposureCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    private val httpClient: SupabaseHttpClient = SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "Anonymer Lesezugriff auf Tabellen"
    override val description =
        "Discovery: enumeriert über den Service-Role-Key alle Tabellen aus der OpenAPI-Spec von /rest/v1/. " +
            "Probing: ruft jede Tabelle anschließend MIT DEM ANON-KEY per GET ?limit=1 ab, um zu sehen, " +
            "was ein unauthentifizierter Browser-Client tatsächlich lesen kann. Tabellen mit sensiblen " +
            "Namen (user, auth, secret, token, …) werden bei anonymem Zugriff härter bewertet."
    override val category = "Supabase / RLS & API-Surface"

    private val json = Json { ignoreUnknownKeys = true }

    private val sensitivePatterns = listOf(
        "user", "profile", "account", "auth", "secret", "credential",
        "token", "session", "password", "payment", "billing", "invoice",
        "card", "bank", "audit", "log", "private",
    )

    override fun run(): CheckResult {
        val start = Instant.now()
        val findings = mutableListOf<Finding>()

        // Discovery via SERVICE-ROLE: der Anon-Key kriegt die OpenAPI-Spec auf /rest/v1/
        // bei Supabase-Standard-Härtung meistens nicht. Service-Role umgeht das.
        log.info { "Discovery: lade OpenAPI-Spec von ${config.baseUrl}/rest/v1/ (Service-Role)" }
        val specResult = runCatching { httpClient.getWithKey("/rest/v1/", config.serviceRoleKey) }
        if (specResult.isFailure) {
            val ex = specResult.exceptionOrNull()
            return errorResult(
                start,
                "OpenAPI-Spec konnte mit Service-Role-Key nicht abgerufen werden: " +
                    "${ex?.message ?: ex?.javaClass?.simpleName}",
            )
        }
        val specResponse = specResult.getOrNull()!!

        if (!specResponse.isSuccess) {
            findings += Finding(
                CheckStatus.YELLOW,
                "OpenAPI-Spec auch mit Service-Role-Key nicht abrufbar (HTTP ${specResponse.statusCode})",
                "GET /rest/v1/ liefert mit der service_role-Rolle keinen Erfolgsstatus. Das ist " +
                    "ungewöhnlich — service_role hat normalerweise uneingeschränkten Zugriff. " +
                    "Ohne Spec können keine Tabellen für das Anon-Probing enumeriert werden.",
                evidence = specResponse.body.take(400),
            )
            return CheckResult(
                checkId = id, checkName = name, checkDescription = description, category = category,
                status = CheckStatus.YELLOW,
                summary = "Schema-Discovery (Service-Role) fehlgeschlagen (HTTP ${specResponse.statusCode}). Manuelle Stichproben empfohlen.",
                findings = findings,
                executedAt = start,
                durationMs = Duration.between(start, Instant.now()).toMillis(),
            )
        }

        val tables = parseTableNames(specResponse.body)
        findings += Finding(
            CheckStatus.GREEN,
            "Discovery: ${tables.size} Tabelle(n) über Service-Role gefunden",
            "Die OpenAPI-Spec wurde mit dem Service-Role-Key geladen. Jede gefundene Tabelle wird " +
                "anschließend mit dem Anon-Key auf öffentliche Lesbarkeit geprüft.",
        )

        if (tables.isEmpty()) {
            return CheckResult(
                checkId = id, checkName = name, checkDescription = description, category = category,
                status = CheckStatus.GREEN,
                summary = "0 Tabellen exponiert.",
                findings = findings,
                executedAt = start,
                durationMs = Duration.between(start, Instant.now()).toMillis(),
            )
        }

        var redCount = 0
        var yellowCount = 0
        var greenCount = 0

        log.info { "Discovery fertig: ${tables.size} Tabelle(n) gefunden — starte anonymous probing" }

        for ((index, table) in tables.withIndex()) {
            val probeStart = Instant.now()
            log.info { "  [${index + 1}/${tables.size}] probe '$table'" }
            val probe = runCatching { httpClient.getWithKey("/rest/v1/$table?limit=1", config.anonKey) }
            val r = probe.getOrNull()
            if (r == null) {
                val ms = Duration.between(probeStart, Instant.now()).toMillis()
                log.info { "  [${index + 1}/${tables.size}] probe '$table' → Exception nach ${ms}ms: ${probe.exceptionOrNull()?.message}" }
                findings += Finding(
                    CheckStatus.YELLOW,
                    "Tabelle '$table': Probe fehlgeschlagen",
                    "GET /rest/v1/$table?limit=1 hat eine Ausnahme geworfen: ${probe.exceptionOrNull()?.message}",
                )
                yellowCount++
                continue
            }
            val ms = Duration.between(probeStart, Instant.now()).toMillis()
            log.info { "  [${index + 1}/${tables.size}] probe '$table' → HTTP ${r.statusCode} (${ms}ms)" }
            when {
                r.statusCode == 200 -> {
                    val rowCount = countRows(r.body)
                    val isSensitive = isSensitiveName(table)
                    when {
                        rowCount > 0 && isSensitive -> {
                            findings += Finding(
                                CheckStatus.RED,
                                "Sensible Tabelle '$table' liefert anonym Daten",
                                "GET /rest/v1/$table?limit=1 → HTTP 200 mit $rowCount Zeile(n). " +
                                    "Der Tabellenname klingt sensibel — RLS-Policies dringend prüfen.",
                                evidence = r.body.take(400),
                            )
                            redCount++
                        }
                        rowCount > 0 -> {
                            findings += Finding(
                                CheckStatus.YELLOW,
                                "Tabelle '$table' liefert anonym Daten",
                                "GET /rest/v1/$table?limit=1 → HTTP 200 mit $rowCount Zeile(n). " +
                                    "Falls bewusst öffentlich (z. B. CMS-Inhalte), ist alles in Ordnung — sonst RLS schärfen.",
                                evidence = r.body.take(400),
                            )
                            yellowCount++
                        }
                        else -> {
                            findings += Finding(
                                CheckStatus.GREEN,
                                "Tabelle '$table' antwortet anonym mit leerem Result",
                                "GET /rest/v1/$table?limit=1 → HTTP 200, []. Tabelle ist entweder leer oder RLS blendet alle Zeilen aus.",
                            )
                            greenCount++
                        }
                    }
                }
                r.statusCode in listOf(401, 403, 404, 406) -> {
                    findings += Finding(
                        CheckStatus.GREEN,
                        "Tabelle '$table' blockiert anonyme Zugriffe (HTTP ${r.statusCode})",
                        "GET /rest/v1/$table?limit=1 wurde wie gewünscht abgelehnt.",
                    )
                    greenCount++
                }
                else -> {
                    findings += Finding(
                        CheckStatus.YELLOW,
                        "Tabelle '$table' antwortet ungewöhnlich (HTTP ${r.statusCode})",
                        "Weder Erfolg noch klare Ablehnung. Manuell prüfen.",
                        evidence = r.body.take(400),
                    )
                    yellowCount++
                }
            }
        }

        val status = CheckStatus.worstOf(findings.map { it.severity })
        val summary = "${tables.size} Tabelle(n) geprüft: $greenCount blockiert/leer, $yellowCount Warnung(en), $redCount kritisch."
        return CheckResult(
            checkId = id, checkName = name, checkDescription = description, category = category,
            status = status,
            summary = summary,
            findings = findings,
            executedAt = start,
            durationMs = Duration.between(start, Instant.now()).toMillis(),
        )
    }

    private fun parseTableNames(specBody: String): List<String> = runCatching {
        val root = json.parseToJsonElement(specBody).jsonObject
        val definitions = root["definitions"] as? JsonObject ?: return emptyList()
        definitions.keys.toList().sorted()
    }.getOrElse { emptyList() }

    private fun countRows(body: String): Int = runCatching {
        (json.parseToJsonElement(body) as? JsonArray)?.size ?: 0
    }.getOrDefault(0)

    private fun isSensitiveName(table: String): Boolean {
        val lower = table.lowercase()
        return sensitivePatterns.any { lower.contains(it) }
    }

    private fun errorResult(start: Instant, message: String): CheckResult = CheckResult(
        checkId = id, checkName = name, checkDescription = description, category = category,
        status = CheckStatus.ERROR,
        summary = message,
        findings = emptyList(),
        executedAt = start,
        durationMs = Duration.between(start, Instant.now()).toMillis(),
        errorMessage = message,
    )
}

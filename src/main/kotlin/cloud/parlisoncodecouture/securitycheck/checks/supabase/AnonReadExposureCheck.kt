package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.core.CheckResult
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import cloud.parlisoncodecouture.securitycheck.core.Finding
import cloud.parlisoncodecouture.securitycheck.core.SecurityCheck
import cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.time.Duration
import java.time.Instant

class AnonReadExposureCheck(
    private val config: cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig,
    private val httpClient: cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient = _root_ide_package_.cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient(
        config
    ),
) : cloud.parlisoncodecouture.securitycheck.core.SecurityCheck {
    override val id = "supabase.anon-read-exposure"
    override val name = "Anonymer Lesezugriff auf Tabellen"
    override val description =
        "Liest mit dem Anon-Key das OpenAPI-Schema der PostgREST-API (/rest/v1/) aus und probiert " +
            "pro Tabelle einen GET ?limit=1. Tabellen mit sensiblen Namen (user, auth, secret, token, …) " +
            "werden bei anonymem Zugriff härter bewertet."
    override val category = "Supabase / RLS & API-Surface"

    private val json = Json { ignoreUnknownKeys = true }

    private val sensitivePatterns = listOf(
        "user", "profile", "account", "auth", "secret", "credential",
        "token", "session", "password", "payment", "billing", "invoice",
        "card", "bank", "audit", "log", "private",
    )

    override fun run(): cloud.parlisoncodecouture.securitycheck.core.CheckResult {
        val start = Instant.now()
        val findings = mutableListOf<cloud.parlisoncodecouture.securitycheck.core.Finding>()

        val specResult = runCatching { httpClient.getWithKey("/rest/v1/", config.anonKey) }
        if (specResult.isFailure) {
            val ex = specResult.exceptionOrNull()
            return errorResult(start, "OpenAPI-Spec konnte nicht abgerufen werden: ${ex?.message ?: ex?.javaClass?.simpleName}")
        }
        val specResponse = specResult.getOrNull()!!

        if (!specResponse.isSuccess) {
            findings += _root_ide_package_.cloud.parlisoncodecouture.securitycheck.core.Finding(
                _root_ide_package_.cloud.parlisoncodecouture.securitycheck.core.CheckStatus.YELLOW,
                "OpenAPI-Spec nicht abrufbar (HTTP ${specResponse.statusCode})",
                "GET /rest/v1/ liefert keinen Erfolgsstatus. Wenn die Spec bewusst deaktiviert ist, ist das " +
                        "ein guter Default — die Tabellen-Aufzählung dieses Checks funktioniert dann aber nicht.",
                evidence = specResponse.body.take(400),
            )
            return _root_ide_package_.cloud.parlisoncodecouture.securitycheck.core.CheckResult(
                checkId = id, checkName = name, checkDescription = description, category = category,
                status = _root_ide_package_.cloud.parlisoncodecouture.securitycheck.core.CheckStatus.YELLOW,
                summary = "Schema konnte nicht enumeriert werden (HTTP ${specResponse.statusCode}). Manuelle Stichproben empfohlen.",
                findings = findings,
                executedAt = start,
                durationMs = Duration.between(start, Instant.now()).toMillis(),
            )
        }

        val tables = parseTableNames(specResponse.body)
        if (tables.isEmpty()) {
            findings += _root_ide_package_.cloud.parlisoncodecouture.securitycheck.core.Finding(
                _root_ide_package_.cloud.parlisoncodecouture.securitycheck.core.CheckStatus.GREEN,
                "Keine Tabellen über die Anon-API erreichbar",
                "Die OpenAPI-Spec enthält keine Definitionen — anonyme API-Surface ist leer.",
            )
            return _root_ide_package_.cloud.parlisoncodecouture.securitycheck.core.CheckResult(
                checkId = id, checkName = name, checkDescription = description, category = category,
                status = _root_ide_package_.cloud.parlisoncodecouture.securitycheck.core.CheckStatus.GREEN,
                summary = "0 Tabellen anonym sichtbar.",
                findings = findings,
                executedAt = start,
                durationMs = Duration.between(start, Instant.now()).toMillis(),
            )
        }

        var redCount = 0
        var yellowCount = 0
        var greenCount = 0

        for (table in tables) {
            val probe = runCatching { httpClient.getWithKey("/rest/v1/$table?limit=1", config.anonKey) }
            val r = probe.getOrNull()
            if (r == null) {
                findings += Finding(
                    CheckStatus.YELLOW,
                    "Tabelle '$table': Probe fehlgeschlagen",
                    "GET /rest/v1/$table?limit=1 hat eine Ausnahme geworfen: ${probe.exceptionOrNull()?.message}",
                )
                yellowCount++
                continue
            }
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

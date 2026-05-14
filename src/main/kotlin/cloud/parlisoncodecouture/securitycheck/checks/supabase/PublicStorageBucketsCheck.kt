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
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant

@CheckId(name = "public-storage-buckets")
class PublicStorageBucketsCheck @JvmOverloads constructor(
    private val config: SupabaseConfig,
    private val httpClient: SupabaseHttpClient = SupabaseHttpClient(config),
) : SecurityCheck {
    override val name = "Public Storage Buckets"
    override val description =
        "Listet alle Storage-Buckets via /storage/v1/bucket (service_role) und prüft das 'public'-Flag. " +
            "Public Buckets sind valide für Avatare/Logos — bei sensiblen Namen (private, document, …) ist es ein Befund."
    override val category = "Supabase / Storage"

    private val json = Json { ignoreUnknownKeys = true }

    private val sensitivePatterns = listOf(
        "private", "internal", "document", "doc", "upload", "file", "user", "secret", "backup", "invoice",
    )

    override fun run(): CheckResult {
        val start = Instant.now()
        val response = runCatching {
            httpClient.getWithKey("/storage/v1/bucket", config.serviceRoleKey)
        }.getOrElse {
            return resultOf(
                findings = listOf(Finding(CheckStatus.ERROR, "Storage-API nicht erreichbar", it.message ?: it::class.simpleName!!)),
                summary = "Aufruf fehlgeschlagen.",
                start = start,
            )
        }

        if (!response.isSuccess) {
            return resultOf(
                findings = listOf(
                    Finding(
                        CheckStatus.YELLOW,
                        "Storage-Bucket-Liste nicht abrufbar (HTTP ${response.statusCode})",
                        "GET /storage/v1/bucket lieferte keinen Erfolg. Service-Role-Key prüfen.",
                        evidence = response.body.take(400),
                    ),
                ),
                summary = "Bucket-Listing fehlgeschlagen (HTTP ${response.statusCode}).",
                start = start,
            )
        }

        val buckets = runCatching { json.parseToJsonElement(response.body).jsonArray }.getOrElse {
            return resultOf(
                findings = listOf(Finding(CheckStatus.ERROR, "Antwort ist kein JSON-Array", response.body.take(200))),
                summary = "Antwort nicht parsebar.",
                start = start,
            )
        }

        if (buckets.isEmpty()) {
            return resultOf(
                findings = listOf(Finding(CheckStatus.GREEN, "Keine Storage-Buckets vorhanden", "Nichts zu prüfen.")),
                summary = "0 Buckets.",
                start = start,
            )
        }

        val findings = mutableListOf<Finding>()
        var publicCount = 0
        for (b in buckets) {
            val obj = (b as? JsonObject) ?: continue
            val name = obj["name"]?.jsonPrimitive?.content ?: "?"
            val isPublic = obj["public"]?.jsonPrimitive?.booleanOrNull ?: false
            val isSensitiveName = sensitivePatterns.any { name.lowercase().contains(it) }
            when {
                isPublic && isSensitiveName -> {
                    findings += Finding(
                        CheckStatus.RED,
                        "Bucket '$name': PUBLIC mit sensitivem Namen",
                        "Der Bucket ist public lesbar (read-all). Name suggeriert nicht-öffentliche Inhalte — Auflistbarkeit aller Files plus direkter Download möglich.",
                    )
                    publicCount++
                }
                isPublic -> {
                    findings += Finding(
                        CheckStatus.YELLOW,
                        "Bucket '$name': PUBLIC",
                        "Jeder kennt-die-URL kann Dateien lesen. Bei Avatar-/Logo-Buckets in Ordnung, bei allem anderen prüfen.",
                    )
                    publicCount++
                }
                else -> {
                    findings += Finding(
                        CheckStatus.GREEN,
                        "Bucket '$name': privat",
                        "Zugriff via storage.objects-Policies geregelt.",
                    )
                }
            }
        }
        val summary = "${buckets.size} Bucket(s): $publicCount public, ${buckets.size - publicCount} privat."
        return resultOf(findings, summary, start)
    }
}

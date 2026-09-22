package cloud.parlisoncodecouture.securitycheck.db

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import cloud.parlisoncodecouture.securitycheck.http.SupabaseHttpClient
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

private val log = KotlinLogging.logger {}

/**
 * Führt die Katalog-Queries über die Supabase Management-API aus — ohne DB-Passwort, nur mit
 * einem Personal Access Token (SUPABASE_ACCESS_TOKEN).
 *
 * Wichtig zur Einordnung: Ein PAT ist account-weit und deutlich mächtiger als ein DB-Passwort
 * (er kann u. a. Projekte löschen). Die Read-only-Zusage ist hier — anders als bei [JdbcCatalogSource]
 * mit erzwungenem Connection.readOnly — nur so stark wie der `read_only`-Parameter der API und
 * unser eigener Code. Deshalb wird ausschließlich SQL aus [CatalogQuery] gesendet.
 */
class ManagementApiCatalogSource(
    private val config: SupabaseConfig,
    private val http: SupabaseHttpClient = SupabaseHttpClient(config),
) : CatalogSource {

    override val kind = CatalogSourceKind.MANAGEMENT_API

    private val projectRef: String = config.projectRef
        ?: error("Management-API braucht die project ref. supabase.project.ref setzen oder supabase.url=https://<ref>.supabase.co verwenden.")

    private val token: String = config.managementApiToken
        ?: error("Management-API-Token fehlt. SUPABASE_ACCESS_TOKEN (Env) oder -Dsupabase.access.token=... setzen.")

    private val endpoint = "${config.managementApiUrl.trimEnd('/')}/v1/projects/$projectRef/database/query"

    override val provenance: String get() = "Live via Management-API (Projekt $projectRef)"

    private val mutableWarnings = mutableListOf<String>()
    override val warnings: List<String> get() = mutableWarnings.toList()

    /** Pro Lauf wird jede Query höchstens einmal gestellt — die Management-API ist rate-limitiert. */
    private val cache = mutableMapOf<String, List<Row>>()

    @Volatile
    private var readOnlySupported = true

    override fun query(query: CatalogQuery): List<Row> =
        cache.getOrPut(query.id) { execute(query.statement()) }

    private fun execute(sql: String): List<Row> {
        var response = post(sql, readOnly = readOnlySupported)

        // Ältere Deployments der API kennen den read_only-Parameter noch nicht.
        if (!response.isSuccess && readOnlySupported && response.body.contains("read_only", ignoreCase = true)) {
            log.warn { "Management-API akzeptiert 'read_only' nicht — wiederhole ohne den Parameter." }
            mutableWarnings += "Die Management-API dieses Projekts kennt den read_only-Parameter nicht. " +
                "Die Abfragen sind weiterhin reine SELECTs, laufen aber ohne serverseitig erzwungene Read-only-Transaktion."
            readOnlySupported = false
            response = post(sql, readOnly = false)
        }

        if (!response.isSuccess) throw ManagementApiException(response.statusCode, endpoint, response.body)

        val root = runCatching { JSON.parseToJsonElement(response.body) }
            .getOrElse { throw ManagementApiException(response.statusCode, endpoint, "Antwort ist kein gültiges JSON: ${it.message}") }

        val array = when (root) {
            is JsonArray -> root
            // Manche Varianten antworten mit { "result": [...] }.
            is JsonObject -> (root["result"] as? JsonArray)
                ?: (root["data"] as? JsonArray)
                ?: throw ManagementApiException(response.statusCode, endpoint, "Unerwartete Antwortstruktur: ${response.body.take(300)}")
            else -> throw ManagementApiException(response.statusCode, endpoint, "Unerwartete Antwortstruktur: ${response.body.take(300)}")
        }
        return array.mapNotNull { (it as? JsonObject)?.let(::JsonRow) }
    }

    private fun post(sql: String, readOnly: Boolean) = http.postJsonBearer(
        absoluteUrl = endpoint,
        bearerToken = token,
        jsonBody = buildJsonObject {
            put("query", sql)
            if (readOnly) put("read_only", true)
        }.toString(),
    )

    private companion object {
        val JSON = Json { ignoreUnknownKeys = true; isLenient = true }
    }
}

class ManagementApiException(status: Int, endpoint: String, body: String) : RuntimeException(
    buildString {
        append("Management-API-Aufruf fehlgeschlagen (HTTP $status) auf $endpoint")
        when (status) {
            401, 403 -> append(
                ". Token ungültig, abgelaufen oder ohne Zugriff auf dieses Projekt. " +
                    "Neues Personal Access Token unter https://supabase.com/dashboard/account/tokens erzeugen " +
                    "und als SUPABASE_ACCESS_TOKEN setzen.",
            )
            404 -> append(
                ". Projekt nicht gefunden oder dein Account ist nicht Mitglied der zugehörigen Organisation. " +
                    "supabase.project.ref prüfen.",
            )
            429 -> append(". Rate-Limit der Management-API erreicht — später erneut versuchen.")
        }
        append(" Antwort: ").append(body.take(500))
    }
)

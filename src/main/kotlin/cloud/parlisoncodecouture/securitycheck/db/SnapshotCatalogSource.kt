package cloud.parlisoncodecouture.securitycheck.db

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Liest Katalogdaten aus einer manuell erhobenen JSON-Datei — dem Ergebnis des von
 * [SnapshotSql] erzeugten Statements, im SQL-Editor ausgeführt und als JSON exportiert.
 *
 * Der Parser ist bewusst nachsichtig gegenüber Export-Varianten (Array vs. { "rows": [...] },
 * payload als Objekt vs. als JSON-String), aber streng bei der Identität: passt die project_ref
 * nicht zum aktiven Profil, bricht der Lauf ab, statt fremde Daten auszuwerten.
 */
class SnapshotCatalogSource private constructor(
    private val path: Path,
    private val rowsById: Map<String, List<Row>>,
    private val meta: SnapshotMeta?,
    override val warnings: List<String>,
) : CatalogSource {

    override val kind = CatalogSourceKind.SNAPSHOT

    override val provenance: String
        get() {
            val captured = meta?.capturedAt?.let { DISPLAY.format(it) }
            return if (captured != null) {
                "Manueller Snapshot vom $captured ($path)"
            } else {
                "Manueller Snapshot ($path)"
            }
        }

    override fun query(query: CatalogQuery): List<Row> {
        rowsById[query.id]?.let { return it }
        // Kein Eintrag: leeres Ergebnis oder gar nicht exportiert? Die meta-Zeile weiß es.
        val exported = meta?.exportedQueryIds
        if (exported == null || query.id in exported) return emptyList()
        throw CatalogQueryMissingException(
            query,
            "Query '${query.id}' fehlt im Snapshot $path. Snapshot mit dem aktuellen Statement neu " +
                "erheben: -Dmode=sql-export erzeugt es.",
        )
    }

    data class SnapshotMeta(
        val profile: String?,
        val projectRef: String?,
        val capturedAt: Instant?,
        val exportedQueryIds: Set<String>?,
        val database: String?,
        val serverVersion: String?,
    )

    companion object {
        private val JSON = Json { ignoreUnknownKeys = true; isLenient = true }
        private val DISPLAY = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss z").withZone(ZoneId.systemDefault())

        private val QUERY_ID_KEYS = listOf("query_id", "queryId", "queryid")
        private val PAYLOAD_KEYS = listOf("payload", "row", "data", "value")
        private val ENVELOPE_KEYS = listOf("rows", "data", "result", "results")

        fun exists(config: SupabaseConfig): Boolean = Files.isRegularFile(config.snapshotPath)

        fun load(config: SupabaseConfig): SnapshotCatalogSource {
            val path = config.snapshotPath
            if (!Files.isRegularFile(path)) throw SnapshotNotFoundException(path, config.activeProfile)

            val text = Files.readString(path)
            val root = runCatching { JSON.parseToJsonElement(text) }
                .getOrElse { throw SnapshotFormatException(path, "Datei ist kein gültiges JSON: ${it.message}") }

            val entries = unwrap(root)
                ?: throw SnapshotFormatException(
                    path,
                    "Erwartet wird ein JSON-Array von { query_id, payload }-Objekten (oder ein Objekt mit " +
                        "'rows'/'data'). Gefunden: ${root::class.simpleName}.",
                )

            val grouped = LinkedHashMap<String, MutableList<Row>>()
            var metaPayload: JsonObject? = null
            var skipped = 0

            for (entry in entries) {
                val obj = entry as? JsonObject
                if (obj == null) { skipped++; continue }
                val queryId = QUERY_ID_KEYS.firstNotNullOfOrNull { (obj[it] as? JsonPrimitive)?.contentOrNullSafe() }
                val payload = PAYLOAD_KEYS.firstNotNullOfOrNull { obj[it]?.asObject() }
                if (queryId == null || payload == null) { skipped++; continue }
                if (queryId == SnapshotSql.META_QUERY_ID) {
                    metaPayload = payload
                } else {
                    grouped.getOrPut(queryId) { mutableListOf() } += JsonRow(payload)
                }
            }

            val meta = metaPayload?.let(::parseMeta)
            val warnings = validate(path, config, meta, grouped.keys, skipped)

            return SnapshotCatalogSource(path, grouped, meta, warnings)
        }

        /** Akzeptiert das nackte Array ebenso wie einen Wrapper { "rows": [...] }. */
        private fun unwrap(root: JsonElement): List<JsonElement>? = when (root) {
            is JsonArray -> root
            is JsonObject -> ENVELOPE_KEYS.firstNotNullOfOrNull { root[it] as? JsonArray }
            else -> null
        }

        private fun parseMeta(payload: JsonObject): SnapshotMeta {
            val capturedRaw = (payload["captured_at"] as? JsonPrimitive)?.contentOrNullSafe()
            val capturedAt = capturedRaw?.let { raw ->
                runCatching { Instant.parse(raw) }
                    // Postgres liefert je nach Formatierung auch '2026-09-22 12:00:00+00'.
                    .recoverCatching { Instant.parse(raw.replace(' ', 'T').let { if (it.endsWith("Z")) it else "${it}Z" }) }
                    .getOrNull()
            }
            return SnapshotMeta(
                profile = (payload["profile"] as? JsonPrimitive)?.contentOrNullSafe(),
                projectRef = (payload["project_ref"] as? JsonPrimitive)?.contentOrNullSafe(),
                capturedAt = capturedAt,
                exportedQueryIds = (payload["queries"] as? JsonArray)
                    ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNullSafe() }
                    ?.toSet(),
                database = (payload["database"] as? JsonPrimitive)?.contentOrNullSafe(),
                serverVersion = (payload["server_version"] as? JsonPrimitive)?.contentOrNullSafe(),
            )
        }

        /**
         * Identität hart, Alter weich: ein fremder Snapshot würde jeden Befund verfälschen und
         * bricht deshalb ab; ein alter Snapshot ist auswertbar, aber kennzeichnungspflichtig.
         */
        private fun validate(
            path: Path,
            config: SupabaseConfig,
            meta: SnapshotMeta?,
            presentIds: Set<String>,
            skipped: Int,
        ): List<String> {
            val warnings = mutableListOf<String>()

            val expectedRef = config.projectRef
            val actualRef = meta?.projectRef
            if (expectedRef != null && actualRef != null && actualRef != "unknown" && !actualRef.equals(expectedRef, ignoreCase = true)) {
                throw SnapshotMismatchException(path, expectedRef, actualRef)
            }

            if (meta == null) {
                warnings += "Snapshot ohne meta-Zeile: Alter und Vollständigkeit sind nicht prüfbar. " +
                    "Neu erheben mit dem aktuellen Statement (-Dmode=sql-export)."
            } else {
                if (actualRef == null) {
                    warnings += "Snapshot nennt keine project_ref — Zuordnung zum Projekt nicht verifizierbar."
                }
                meta.capturedAt?.let { captured ->
                    val ageDays = Duration.between(captured, Instant.now()).toDays()
                    if (ageDays > config.snapshotMaxAgeDays) {
                        warnings += "Snapshot ist $ageDays Tage alt (Grenze: ${config.snapshotMaxAgeDays}). " +
                            "Die Befunde beschreiben den Stand vom ${DISPLAY.format(captured)}, nicht den heutigen."
                    }
                } ?: run {
                    warnings += "Snapshot ohne lesbares captured_at — das Alter der Daten ist unbekannt."
                }
                meta.exportedQueryIds?.let { exported ->
                    val unknown = exported - CatalogQuery.entries.map { it.id }.toSet()
                    if (unknown.isNotEmpty()) {
                        warnings += "Snapshot enthält unbekannte Queries (${unknown.joinToString()}) — " +
                            "vermutlich mit einer neueren Version des Tools erhoben."
                    }
                    val missing = CatalogQuery.entries.map { it.id }.toSet() - exported
                    if (missing.isNotEmpty()) {
                        warnings += "Snapshot deckt nicht alle Queries ab; es fehlen: ${missing.joinToString()}. " +
                            "Die zugehörigen Checks werden übersprungen."
                    }
                }
            }

            val orphaned = presentIds - CatalogQuery.entries.map { it.id }.toSet()
            if (orphaned.isNotEmpty()) {
                warnings += "Zeilen mit unbekannter query_id im Snapshot ignoriert: ${orphaned.joinToString()}."
            }
            if (skipped > 0) {
                warnings += "$skipped Zeile(n) im Snapshot ohne verwertbares query_id/payload-Paar übersprungen."
            }
            return warnings
        }

        private fun JsonPrimitive.contentOrNullSafe(): String? = content.takeIf { it.isNotBlank() && it != "null" }

        /** payload kann als Objekt oder — je nach Export — als JSON-String ankommen. */
        private fun JsonElement.asObject(): JsonObject? = when (this) {
            is JsonObject -> this
            is JsonPrimitive -> if (isString) runCatching { JSON.parseToJsonElement(content) as? JsonObject }.getOrNull() else null
            else -> null
        }
    }
}

class SnapshotNotFoundException(path: Path, profile: String?) : RuntimeException(
    buildString {
        appendLine("Katalog-Snapshot nicht gefunden:")
        appendLine("  $path")
        appendLine()
        appendLine("So legst du ihn an:")
        appendLine("  1. mvn -q compile exec:java -Dactive.profile=${profile ?: "<profil>"} -Dmode=sql-export")
        appendLine("  2. Das erzeugte SQL im Supabase SQL-Editor ausführen")
        appendLine("  3. Ergebnis als JSON exportieren und unter obigem Pfad ablegen")
    }.trim()
)

class SnapshotFormatException(path: Path, detail: String) : RuntimeException(
    "Katalog-Snapshot $path ist nicht lesbar: $detail"
)

class SnapshotMismatchException(path: Path, expectedRef: String, actualRef: String) : RuntimeException(
    "Katalog-Snapshot $path gehört zu Projekt '$actualRef', das aktive Profil zeigt aber auf " +
        "'$expectedRef'. Lauf abgebrochen — ein fremder Snapshot würde jeden Befund verfälschen."
)

package cloud.parlisoncodecouture.securitycheck.db

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Eine Ergebniszeile — unabhängig davon, ob sie aus einem JDBC-ResultSet, aus der Management-API
 * oder aus einem manuell erhobenen JSON-Snapshot stammt.
 *
 * Die Check-Mapper greifen nur über dieses Interface zu; damit ist der Auswertungscode identisch,
 * egal welche CatalogSource die Daten geliefert hat.
 */
interface Row {
    fun string(column: String): String?
    fun boolean(column: String): Boolean
    fun int(column: String): Int

    /** Postgres text[]/name[] (z. B. reloptions, roles, proconfig) als Liste. */
    fun textArray(column: String): List<String>
}

/**
 * Zeile aus bereits ausgelesenen Werten. JDBC materialisiert hierhin, damit die Connection
 * geschlossen werden kann, bevor die Checks mappen.
 */
class MaterializedRow(private val values: Map<String, Any?>) : Row {

    private fun raw(column: String): Any? = values[column] ?: values[column.lowercase()]

    override fun string(column: String): String? = when (val v = raw(column)) {
        null -> null
        is String -> v
        else -> v.toString()
    }

    override fun boolean(column: String): Boolean = when (val v = raw(column)) {
        null -> false
        is Boolean -> v
        is Number -> v.toInt() != 0
        else -> parseBoolean(v.toString())
    }

    override fun int(column: String): Int = when (val v = raw(column)) {
        null -> 0
        is Number -> v.toInt()
        else -> v.toString().trim().toIntOrNull() ?: 0
    }

    @Suppress("UNCHECKED_CAST")
    override fun textArray(column: String): List<String> = when (val v = raw(column)) {
        null -> emptyList()
        is List<*> -> v.mapNotNull { it?.toString() }
        is Array<*> -> v.mapNotNull { it?.toString() }
        is String -> parsePgArrayLiteral(v)
        else -> emptyList()
    }
}

/** Zeile aus einem JSON-Objekt (Snapshot-Datei oder Management-API-Response). */
class JsonRow(private val obj: JsonObject) : Row {

    private fun element(column: String) = obj[column] ?: obj[column.lowercase()]

    override fun string(column: String): String? = when (val e = element(column)) {
        null, JsonNull -> null
        is JsonPrimitive -> if (e.isString) e.content else e.content
        else -> e.toString()
    }

    override fun boolean(column: String): Boolean {
        val e = element(column)
        if (e !is JsonPrimitive || e is JsonNull) return false
        return parseBoolean(e.content)
    }

    override fun int(column: String): Int {
        val e = element(column)
        if (e !is JsonPrimitive || e is JsonNull) return 0
        return e.content.trim().toIntOrNull() ?: 0
    }

    override fun textArray(column: String): List<String> = when (val e = element(column)) {
        null, JsonNull -> emptyList()
        // to_jsonb() liefert echte JSON-Arrays für text[]/name[].
        is JsonArray -> e.mapNotNull { item ->
            when (item) {
                JsonNull -> null
                is JsonPrimitive -> item.content
                else -> item.toString()
            }
        }
        // Fallback: manche Exporte reichen das Postgres-Array-Literal '{a,b}' als String durch.
        is JsonPrimitive -> parsePgArrayLiteral(e.content)
        else -> emptyList()
    }
}

private fun parseBoolean(raw: String): Boolean =
    raw.trim().lowercase() in setOf("true", "t", "yes", "y", "on", "1")

/**
 * Parst ein Postgres-Array-Literal wie {a,b,"c,d"}. Nur der Fallback-Pfad — die regulären
 * Quellen liefern echte Arrays.
 */
internal fun parsePgArrayLiteral(raw: String): List<String> {
    val body = raw.trim().removeSurrounding("{", "}")
    if (body.isBlank()) return emptyList()
    val out = mutableListOf<String>()
    val current = StringBuilder()
    var inQuotes = false
    var escaped = false
    for (ch in body) {
        when {
            escaped -> { current.append(ch); escaped = false }
            ch == '\\' -> escaped = true
            ch == '"' -> inQuotes = !inQuotes
            ch == ',' && !inQuotes -> { out += current.toString(); current.clear() }
            else -> current.append(ch)
        }
    }
    out += current.toString()
    return out.map { it.trim() }.filter { it.isNotEmpty() && it != "NULL" }
}

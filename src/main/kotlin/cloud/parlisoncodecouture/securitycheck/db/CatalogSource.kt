package cloud.parlisoncodecouture.securitycheck.db

/** Woher die Katalogdaten stammen. */
enum class CatalogSourceKind(val id: String, val label: String) {
    /** Direkte Postgres-Verbindung mit DB-Passwort, read-only erzwungen. */
    JDBC("jdbc", "JDBC (direkt, read-only)"),

    /** Supabase Management-API mit Personal Access Token — kein DB-Passwort nötig. */
    MANAGEMENT_API("mgmt-api", "Supabase Management-API"),

    /** Manuell im SQL-Editor erhobenes und abgelegtes JSON. */
    SNAPSHOT("snapshot", "Manueller Snapshot"),
    ;

    companion object {
        fun byId(id: String): CatalogSourceKind? = entries.firstOrNull { it.id.equals(id, ignoreCase = true) }
    }
}

/**
 * Liefert die Zeilen einer [CatalogQuery] — egal ob live aus der DB, über die Management-API
 * oder aus einer manuell erhobenen Snapshot-Datei.
 */
interface CatalogSource : AutoCloseable {
    val kind: CatalogSourceKind

    /** Einzeiler für Report-Header und Konsole, z. B. "Manueller Snapshot vom 22.09.2026 14:03". */
    val provenance: String

    /** Nicht-fatale Hinweise zur Datenlage (z. B. veralteter Snapshot). Landen im Report. */
    val warnings: List<String>
        get() = emptyList()

    fun query(query: CatalogQuery): List<Row>

    /**
     * Stellt fest, ob die Quelle wirklich benutzbar ist — VOR der ersten Check-Query.
     * Ohne das gilt eine Quelle als verfügbar, sobald sich das Objekt bauen lässt, und
     * die Fallback-Kette greift nicht mehr (ein falsches DB-Passwort würde den Snapshot
     * verdecken, statt an ihn weiterzureichen).
     */
    fun validate() {}

    override fun close() {}
}

/** Die Quelle kennt die Query nicht — bei Snapshots der häufigste Fall (Teil-Export). */
class CatalogQueryMissingException(val query: CatalogQuery, message: String) : RuntimeException(message)

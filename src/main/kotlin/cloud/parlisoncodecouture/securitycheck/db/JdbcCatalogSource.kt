package cloud.parlisoncodecouture.securitycheck.db

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import java.sql.Array as SqlArray
import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet

/**
 * Direkter read-only Postgres-Zugriff über JDBC/TLS, mit dem DB-Passwort aus
 * SUPABASE_DB_PASSWORD bzw. -Dsupabase.db.password.
 *
 * Die stärkste der drei Quellen, was die Read-only-Zusage angeht: [Connection.setReadOnly]
 * wird vom Treiber erzwungen, nicht nur von unserem Code zugesichert.
 */
class JdbcCatalogSource(private val config: SupabaseConfig) : CatalogSource {

    override val kind = CatalogSourceKind.JDBC

    private val host: String = config.resolvedDbHost()
        ?: error("DB-Host nicht gesetzt und keine projectRef zum Ableiten. Setze db.host oder supabase.url=https://<ref>.supabase.co.")

    override val provenance: String get() = "Live via JDBC ($host:${config.dbPort}/${config.dbName}, read-only)"

    init {
        // Neuere Treiber registrieren sich selbst — defensiv trotzdem laden.
        Class.forName("org.postgresql.Driver")
    }

    private val connection: Connection by lazy {
        val password = config.dbPassword
            ?: error("DB-Passwort fehlt. SUPABASE_DB_PASSWORD (Env) oder -Dsupabase.db.password=... setzen.")
        val jdbcUrl = "jdbc:postgresql://$host:${config.dbPort}/${config.dbName}?sslmode=require"
        DriverManager.setLoginTimeout(config.connectTimeoutSeconds.toInt())
        DriverManager.getConnection(jdbcUrl, config.dbUser, password).also {
            it.isReadOnly = true
        }
    }

    /** Baut die Verbindung auf; schlägt hier fehl, was später bei jeder Query fehlschlagen würde. */
    override fun validate() {
        connection.isValid(config.connectTimeoutSeconds.toInt())
    }

    override fun query(query: CatalogQuery): List<Row> = query(query.statement())

    /** Führt beliebiges SELECT-SQL aus — für den Snapshot-Export als Gegenprobe nutzbar. */
    fun query(sql: String): List<Row> {
        val rows = mutableListOf<Row>()
        connection.prepareStatement(sql).use { stmt ->
            stmt.queryTimeout = config.requestTimeoutSeconds.toInt()
            stmt.executeQuery().use { rs ->
                val columns = (1..rs.metaData.columnCount).map { rs.metaData.getColumnLabel(it) }
                while (rs.next()) rows += materialize(rs, columns)
            }
        }
        return rows
    }

    private fun materialize(rs: ResultSet, columns: List<String>): Row {
        val values = LinkedHashMap<String, Any?>(columns.size)
        for (column in columns) {
            values[column] = when (val raw = rs.getObject(column)) {
                is SqlArray -> (raw.array as? Array<*>)?.mapNotNull { it?.toString() } ?: emptyList<String>()
                else -> raw
            }
        }
        return MaterializedRow(values)
    }

    override fun close() {
        runCatching { connection.close() }
    }
}

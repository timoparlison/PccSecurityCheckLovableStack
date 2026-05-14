package cloud.parlisoncodecouture.securitycheck.db

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import java.sql.Connection
import java.sql.DriverManager
import java.sql.ResultSet

/**
 * Direct read-only Postgres access for the catalog-based checks.
 * Connects with the DB password (from SUPABASE_DB_PASSWORD env / -D) using TLS.
 *
 * The client makes NO schema modifications — it only runs SELECTs against
 * pg_catalog/system views. Nothing is left behind on the target.
 */
class PostgresQueryClient(private val config: SupabaseConfig) : AutoCloseable {

    init {
        // Ensure the JDBC driver is registered (newer drivers auto-register, but be defensive).
        Class.forName("org.postgresql.Driver")
    }

    private val connection: Connection by lazy {
        val host = config.resolvedDbHost()
            ?: error("DB host not set and no projectRef to derive from. Set db.host in properties or supabase.url to https://<ref>.supabase.co.")
        val password = config.dbPassword
            ?: error("DB password missing. Provide SUPABASE_DB_PASSWORD env var or -Dsupabase.db.password=...")
        val jdbcUrl = "jdbc:postgresql://$host:${config.dbPort}/${config.dbName}?sslmode=require"
        DriverManager.setLoginTimeout(config.connectTimeoutSeconds.toInt())
        DriverManager.getConnection(jdbcUrl, config.dbUser, password).also {
            it.isReadOnly = true
        }
    }

    fun <T> query(sql: String, mapper: (ResultSet) -> T): List<T> {
        val rows = mutableListOf<T>()
        connection.prepareStatement(sql).use { stmt ->
            stmt.queryTimeout = config.requestTimeoutSeconds.toInt()
            stmt.executeQuery().use { rs ->
                while (rs.next()) rows.add(mapper(rs))
            }
        }
        return rows
    }

    override fun close() {
        runCatching { connection.close() }
    }
}

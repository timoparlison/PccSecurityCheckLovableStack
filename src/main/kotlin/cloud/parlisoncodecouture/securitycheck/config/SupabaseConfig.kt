package cloud.parlisoncodecouture.securitycheck.config

import cloud.parlisoncodecouture.securitycheck.db.CatalogSourceKind
import java.nio.file.Path

data class SupabaseConfig(
    val activeProfile: String?,
    val url: String,
    val anonKey: String,
    val serviceRoleKey: String,
    val projectRef: String?,
    val connectTimeoutSeconds: Long,
    val requestTimeoutSeconds: Long,
    val frontendUrl: String?,
    val functionsPath: Path?,
    val migrationsPath: Path?,
    val dbHost: String?,
    val dbPort: Int,
    val dbName: String,
    val dbUser: String,
    val dbPassword: String?,
    /** Personal Access Token für die Supabase Management-API — Alternative zum DB-Passwort. */
    val managementApiToken: String?,
    val managementApiUrl: String,
    /** Erzwungene Katalogquelle; null = automatisch wählen (JDBC → Management-API → Snapshot). */
    val catalogSource: CatalogSourceKind?,
    /** Ablageort des manuell erhobenen Katalog-Snapshots. */
    val snapshotPath: Path,
    /** Ab wann ein Snapshot im Report als veraltet markiert wird. */
    val snapshotMaxAgeDays: Long,
    /** Tabellennamen, deren anonyme Lesbarkeit bewusst akzeptiert ist (z. B. 'posts', 'public.articles'). */
    val allowlistTables: Set<String> = emptySet(),
    /** Storage-Bucket-Namen, deren public-Flag bewusst akzeptiert ist (z. B. 'avatars'). */
    val allowlistBuckets: Set<String> = emptySet(),
) {
    val baseUrl: String get() = url.trimEnd('/')
    val restBaseUrl: String get() = "$baseUrl/rest/v1"

    fun resolvedDbHost(): String? = dbHost ?: projectRef?.let { "db.$it.supabase.co" }

    /** Direkter JDBC-Zugang möglich (DB-Passwort + auflösbarer Host). */
    val hasDbAccess: Boolean
        get() = !dbPassword.isNullOrBlank() && !resolvedDbHost().isNullOrBlank()

    /** Management-API nutzbar (PAT + project ref) — braucht kein DB-Passwort. */
    val hasManagementApiAccess: Boolean
        get() = !managementApiToken.isNullOrBlank() && !projectRef.isNullOrBlank()

    /** Case-insensitive Lookup; akzeptiert sowohl 'posts' als auch 'public.posts'. */
    fun isTableAllowlisted(table: String): Boolean {
        if (allowlistTables.isEmpty()) return false
        val lc = table.lowercase()
        val bare = lc.substringAfterLast('.')
        return allowlistTables.any { entry ->
            val e = entry.lowercase()
            e == lc || e == bare || e.substringAfterLast('.') == bare
        }
    }

    fun isBucketAllowlisted(bucket: String): Boolean =
        allowlistBuckets.any { it.equals(bucket, ignoreCase = true) }
}

package cloud.parlisoncodecouture.securitycheck.config

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
    /** Tabellennamen, deren anonyme Lesbarkeit bewusst akzeptiert ist (z. B. 'posts', 'public.articles'). */
    val allowlistTables: Set<String> = emptySet(),
    /** Storage-Bucket-Namen, deren public-Flag bewusst akzeptiert ist (z. B. 'avatars'). */
    val allowlistBuckets: Set<String> = emptySet(),
) {
    val baseUrl: String get() = url.trimEnd('/')
    val restBaseUrl: String get() = "$baseUrl/rest/v1"

    fun resolvedDbHost(): String? = dbHost ?: projectRef?.let { "db.$it.supabase.co" }

    val hasDbAccess: Boolean
        get() = !dbPassword.isNullOrBlank() && !resolvedDbHost().isNullOrBlank()

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

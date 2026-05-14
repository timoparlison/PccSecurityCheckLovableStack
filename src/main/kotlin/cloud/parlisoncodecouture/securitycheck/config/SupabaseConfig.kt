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
) {
    val baseUrl: String get() = url.trimEnd('/')
    val restBaseUrl: String get() = "$baseUrl/rest/v1"

    fun resolvedDbHost(): String? = dbHost ?: projectRef?.let { "db.$it.supabase.co" }

    val hasDbAccess: Boolean
        get() = !dbPassword.isNullOrBlank() && !resolvedDbHost().isNullOrBlank()
}

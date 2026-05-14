package cloud.parlisoncodecouture.securitycheck.config

import java.nio.file.Path

data class SupabaseConfig(
    val url: String,
    val anonKey: String,
    val serviceRoleKey: String,
    val projectRef: String?,
    val connectTimeoutSeconds: Long,
    val requestTimeoutSeconds: Long,
    val frontendUrl: String?,
    val functionsPath: Path?,
    val migrationsPath: Path?,
) {
    val baseUrl: String get() = url.trimEnd('/')
    val restBaseUrl: String get() = "$baseUrl/rest/v1"
}

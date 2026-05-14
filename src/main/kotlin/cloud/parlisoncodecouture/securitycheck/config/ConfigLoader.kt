package cloud.parlisoncodecouture.securitycheck.config

import io.github.oshai.kotlinlogging.KotlinLogging
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties
import kotlin.io.path.name

private val log = KotlinLogging.logger {}

object ConfigLoader {
    private const val CONFIG_DIR = "config"
    private val PROFILE_FILE_REGEX = Regex("""supabase-(.+)\.properties""")
    private fun profileFile(profile: String) = "$CONFIG_DIR/supabase-$profile.properties"

    private const val EXPLICIT_FILE_PROP = "supabase.config.file"
    private const val EXPLICIT_FILE_ENV = "SUPABASE_CONFIG_FILE"
    private const val PROFILE_ENV = "ACTIVE_PROFILE"
    private const val PROFILE_PROP = "active.profile"

    private const val SERVICE_ROLE_ENV = "SUPABASE_SERVICE_ROLE_KEY"
    private const val SERVICE_ROLE_PROP = "supabase.service.role.key"

    private const val DB_PASSWORD_ENV = "SUPABASE_DB_PASSWORD"
    private const val DB_PASSWORD_PROP = "supabase.db.password"

    fun load(): SupabaseConfig {
        val (path, profile) = resolveConfigPath()
        if (!Files.exists(path)) throw ConfigNotFoundException(path, profile, discoverProfiles())
        val props = Properties()
        Files.newBufferedReader(path).use { props.load(it) }
        return parse(props, profile)
    }

    private fun resolveConfigPath(): Pair<Path, String?> {
        // Priority: explicit file override > active profile.
        val explicit = System.getProperty(EXPLICIT_FILE_PROP)?.trim()?.ifBlank { null }
            ?: System.getenv(EXPLICIT_FILE_ENV)?.trim()?.ifBlank { null }
        if (explicit != null) {
            val path = Path.of(explicit).toAbsolutePath()
            // Try to derive profile name from filename if it matches the convention.
            val profile = PROFILE_FILE_REGEX.matchEntire(path.name)?.groupValues?.get(1)
            return path to profile
        }
        val profile = System.getenv(PROFILE_ENV)?.trim()?.ifEmpty { null }
            ?: System.getProperty(PROFILE_PROP)?.trim()?.ifEmpty { null }
            ?: throw ActiveProfileMissingException(discoverProfiles())
        return Path.of(profileFile(profile)).toAbsolutePath() to profile
    }

    private fun discoverProfiles(): List<String> {
        val dir = Path.of(CONFIG_DIR)
        if (!Files.isDirectory(dir)) return emptyList()
        return Files.list(dir).use { stream ->
            stream
                .map { it.fileName.toString() }
                .map { PROFILE_FILE_REGEX.matchEntire(it)?.groupValues?.get(1) }
                .filter { it != null }
                .map { it!! }
                .sorted()
                .toList()
        }
    }

    private fun parse(props: Properties, profile: String?): SupabaseConfig {
        val url = required(props, "supabase.url").also { validateUrl(it) }
        val anonKey = required(props, "supabase.anon.key")

        warnIfSecretInFile(props, SERVICE_ROLE_PROP, SERVICE_ROLE_ENV)
        warnIfSecretInFile(props, DB_PASSWORD_PROP, DB_PASSWORD_ENV)

        val serviceRoleKey = readRuntimeSecret(SERVICE_ROLE_ENV, SERVICE_ROLE_PROP)
            ?: throw ServiceRoleKeyMissingException()
        val dbPassword = readRuntimeSecret(DB_PASSWORD_ENV, DB_PASSWORD_PROP)

        val projectRef = props.getProperty("supabase.project.ref")
            ?.trim()?.ifBlank { null }
            ?: inferProjectRef(url)
        val connectTimeout = props.getProperty("http.connect.timeout.seconds")?.toLongOrNull() ?: 10L
        val requestTimeout = props.getProperty("http.request.timeout.seconds")?.toLongOrNull() ?: 20L

        val frontendUrl = props.getProperty("frontend.url")?.trim()?.ifBlank { null }
        val functionsPath = props.getProperty("functions.path")
            ?.trim()?.ifBlank { null }?.let { Path.of(it).toAbsolutePath() }
        val migrationsPath = props.getProperty("migrations.path")
            ?.trim()?.ifBlank { null }?.let { Path.of(it).toAbsolutePath() }

        val dbHost = props.getProperty("db.host")?.trim()?.ifBlank { null }
        val dbPort = props.getProperty("db.port")?.toIntOrNull() ?: 5432
        val dbName = props.getProperty("db.name")?.trim()?.ifBlank { null } ?: "postgres"
        val dbUser = props.getProperty("db.user")?.trim()?.ifBlank { null } ?: "postgres"

        val allowlistTables = parseCsvSet(props.getProperty("allowlist.tables"))
        val allowlistBuckets = parseCsvSet(props.getProperty("allowlist.buckets"))

        return SupabaseConfig(
            activeProfile = profile,
            url = url.trimEnd('/'),
            anonKey = anonKey,
            serviceRoleKey = serviceRoleKey,
            projectRef = projectRef,
            connectTimeoutSeconds = connectTimeout,
            requestTimeoutSeconds = requestTimeout,
            frontendUrl = frontendUrl,
            functionsPath = functionsPath,
            migrationsPath = migrationsPath,
            dbHost = dbHost,
            dbPort = dbPort,
            dbName = dbName,
            dbUser = dbUser,
            dbPassword = dbPassword,
            allowlistTables = allowlistTables,
            allowlistBuckets = allowlistBuckets,
        )
    }

    private fun parseCsvSet(raw: String?): Set<String> =
        raw?.split(',')
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?.toSet()
            ?: emptySet()

    private fun warnIfSecretInFile(props: Properties, key: String, envName: String) {
        if (props.getProperty(key)?.isNotBlank() == true) {
            log.warn {
                "Eintrag '$key' aus der Properties-Datei wird IGNORIERT. " +
                    "Secrets gehören nicht auf die Festplatte — übergib per Env $envName oder -D$key=..."
            }
        }
    }

    private fun readRuntimeSecret(envName: String, propName: String): String? {
        val fromEnv = System.getenv(envName)?.trim()?.ifEmpty { null }
        val fromProp = System.getProperty(propName)?.trim()?.ifEmpty { null }
        return fromEnv ?: fromProp
    }

    private fun required(props: Properties, key: String): String {
        val value = props.getProperty(key)?.trim()
        if (value.isNullOrEmpty()) throw IllegalArgumentException("Missing required config key: $key")
        return value
    }

    private fun validateUrl(url: String) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            throw IllegalArgumentException("supabase.url must start with http(s)://, got: $url")
        }
    }

    private fun inferProjectRef(url: String): String? =
        Regex("""https?://([^.]+)\.supabase\.co""").find(url)?.groupValues?.get(1)
}

class ActiveProfileMissingException(availableProfiles: List<String>) : RuntimeException(
    buildString {
        appendLine("Active profile is not set.")
        appendLine()
        appendLine("Choose a profile via one of:")
        appendLine("  env:  ACTIVE_PROFILE=<profile> mvn -q compile exec:java")
        appendLine("  jvm:  mvn -q compile exec:java -Dactive.profile=<profile>")
        appendLine()
        if (availableProfiles.isEmpty()) {
            appendLine("No profile properties files found in config/.")
            appendLine("Create one by copying the example:")
            appendLine("  cp config/supabase-example.properties config/supabase-<profile>.properties")
        } else {
            appendLine("Available profiles (found in config/):")
            availableProfiles.forEach { appendLine("  - $it") }
        }
    }.trim()
)

class ConfigNotFoundException(path: Path, profile: String?, availableProfiles: List<String>) : RuntimeException(
    buildString {
        appendLine("Supabase config file not found:")
        appendLine("  $path")
        appendLine()
        if (profile != null) appendLine("Requested profile: '$profile'")
        if (availableProfiles.isEmpty()) {
            appendLine("No profile files in config/ yet. Copy the example to create one:")
            appendLine("  cp config/supabase-example.properties config/supabase-${profile ?: "<profile>"}.properties")
        } else {
            appendLine("Available profiles:")
            availableProfiles.forEach { appendLine("  - $it") }
        }
    }.trim()
)

class ServiceRoleKeyMissingException : RuntimeException(
    """
    Supabase service role key is not set.

    For security reasons this key is NEVER read from a file on disk.
    Provide it at runtime via one of:

      env:  SUPABASE_SERVICE_ROLE_KEY=eyJh... mvn -q compile exec:java
      jvm:  mvn -q compile exec:java -Dsupabase.service.role.key=eyJh...

    In IntelliJ: edit the run configuration, add the env variable or
    "-Dsupabase.service.role.key=..." under "VM options".
    """.trimIndent()
)

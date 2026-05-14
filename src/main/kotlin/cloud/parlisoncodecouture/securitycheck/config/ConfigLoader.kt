package cloud.parlisoncodecouture.securitycheck.config

import io.github.oshai.kotlinlogging.KotlinLogging
import java.nio.file.Files
import java.nio.file.Path
import java.util.Properties

private val log = KotlinLogging.logger {}

object ConfigLoader {
    private const val DEFAULT_PATH = "config/supabase.properties"
    private const val SYSTEM_PROPERTY = "supabase.config.file"
    private const val ENV_VARIABLE = "SUPABASE_CONFIG_FILE"

    private const val SERVICE_ROLE_ENV = "SUPABASE_SERVICE_ROLE_KEY"
    private const val SERVICE_ROLE_PROP = "supabase.service.role.key"

    private const val DB_PASSWORD_ENV = "SUPABASE_DB_PASSWORD"
    private const val DB_PASSWORD_PROP = "supabase.db.password"

    fun load(explicitPath: String? = null): SupabaseConfig {
        val path = resolvePath(explicitPath)
        if (!Files.exists(path)) throw ConfigNotFoundException(path)
        val props = Properties()
        Files.newBufferedReader(path).use { props.load(it) }
        return parse(props)
    }

    private fun resolvePath(explicit: String?): Path {
        val raw = explicit
            ?: System.getProperty(SYSTEM_PROPERTY)
            ?: System.getenv(ENV_VARIABLE)
            ?: DEFAULT_PATH
        return Path.of(raw).toAbsolutePath()
    }

    private fun parse(props: Properties): SupabaseConfig {
        val url = required(props, "supabase.url").also { validateUrl(it) }
        val anonKey = required(props, "supabase.anon.key")

        warnIfSecretInFile(props, SERVICE_ROLE_PROP, SERVICE_ROLE_ENV)
        warnIfSecretInFile(props, DB_PASSWORD_PROP, DB_PASSWORD_ENV)

        val serviceRoleKey = readRuntimeSecret(SERVICE_ROLE_ENV, SERVICE_ROLE_PROP)
            ?: throw ServiceRoleKeyMissingException()
        val dbPassword = readRuntimeSecret(DB_PASSWORD_ENV, DB_PASSWORD_PROP) // optional

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

        return SupabaseConfig(
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
        )
    }

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

class ConfigNotFoundException(path: Path) : RuntimeException(
    """
    Supabase config not found at: $path

    Create it by copying the example:
      cp config/supabase.example.properties config/supabase.properties

    Or override the path:
      -Dsupabase.config.file=/abs/path/to.properties
      or env SUPABASE_CONFIG_FILE=/abs/path/to.properties
    """.trimIndent()
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

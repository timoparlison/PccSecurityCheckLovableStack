package cloud.parlisoncodecouture.securitycheck.db

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import io.github.oshai.kotlinlogging.KotlinLogging

private val log = KotlinLogging.logger {}

/**
 * Was ein Check über den Katalogzugang weiß: entweder eine nutzbare Quelle oder der Grund,
 * warum es keine gibt. Der Grund wandert unverändert in die SKIPPED-Meldung des Reports —
 * damit steht dort "Snapshot fehlt, so legst du ihn an" statt nur "kein DB-Zugang".
 */
sealed interface CatalogAccess {

    val sourceOrNull: CatalogSource?
    val reason: String?

    data class Available(
        val source: CatalogSource,
        /** Quellen, die vor dieser probiert und verworfen wurden — gehören sichtbar in den Report. */
        val notes: List<String> = emptyList(),
    ) : CatalogAccess {
        override val sourceOrNull: CatalogSource get() = source
        override val reason: String? get() = null
    }

    data class Unavailable(override val reason: String) : CatalogAccess {
        override val sourceOrNull: CatalogSource? get() = null
    }
}

/**
 * Wählt die Katalogquelle für einen Lauf aus.
 *
 * Reihenfolge im AUTO-Modus: JDBC → Management-API → Snapshot. JDBC zuerst, weil dort die
 * Read-only-Zusage vom Treiber erzwungen wird; Snapshot zuletzt, weil er als einziger nicht
 * den Live-Zustand zeigt. Erzwingen lässt sich eine Quelle über `catalog.source` in den
 * Profil-Properties bzw. -Dcatalog.source=...
 */
object CatalogSources {

    fun resolve(config: SupabaseConfig): CatalogAccess {
        val forced = config.catalogSource
        if (forced != null) {
            return runCatching { create(forced, config).also { it.validate() } }.fold(
                onSuccess = { CatalogAccess.Available(it) },
                onFailure = {
                    CatalogAccess.Unavailable(
                        "Katalogquelle '${forced.id}' wurde per catalog.source erzwungen, ist aber nicht " +
                            "nutzbar: ${it.message ?: it::class.simpleName}",
                    )
                },
            )
        }

        val candidates = listOfNotNull(
            CatalogSourceKind.JDBC.takeIf { config.hasDbAccess },
            CatalogSourceKind.MANAGEMENT_API.takeIf { config.hasManagementApiAccess },
            CatalogSourceKind.SNAPSHOT.takeIf { SnapshotCatalogSource.exists(config) },
        )
        if (candidates.isEmpty()) return CatalogAccess.Unavailable(noSourceHint(config))

        val failures = mutableListOf<String>()
        for (kind in candidates) {
            runCatching { create(kind, config).also { it.validate() } }
                .onSuccess { source ->
                    val notes = failures.map { "Katalogquelle übersprungen — $it" }
                    notes.forEach { log.warn { it } }
                    return CatalogAccess.Available(source, notes)
                }
                .onFailure { failures += "${kind.id}: ${it.message ?: it::class.simpleName}" }
        }
        return CatalogAccess.Unavailable("Keine Katalogquelle nutzbar. ${failures.joinToString("; ")}")
    }

    private fun create(kind: CatalogSourceKind, config: SupabaseConfig): CatalogSource = when (kind) {
        CatalogSourceKind.JDBC -> JdbcCatalogSource(config)
        CatalogSourceKind.MANAGEMENT_API -> ManagementApiCatalogSource(config)
        CatalogSourceKind.SNAPSHOT -> SnapshotCatalogSource.load(config)
    }

    private fun noSourceHint(config: SupabaseConfig): String = buildString {
        append("Kein Zugang zum DB-Katalog. Drei Wege stehen zur Wahl: ")
        append("(1) DB-Passwort per SUPABASE_DB_PASSWORD; ")
        append("(2) Management-API per SUPABASE_ACCESS_TOKEN (Personal Access Token, kein DB-Passwort nötig); ")
        append("(3) manueller Snapshot — SQL erzeugen mit -Dmode=sql-export, im SQL-Editor ausführen, ")
        append("Ergebnis als JSON ablegen unter ${config.snapshotPath}.")
    }
}

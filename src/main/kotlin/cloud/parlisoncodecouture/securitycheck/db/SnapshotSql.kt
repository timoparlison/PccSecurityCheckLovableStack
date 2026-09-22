package cloud.parlisoncodecouture.securitycheck.db

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig

/**
 * Erzeugt das Statement, das jemand mit SQL-Editor-Zugang manuell ausführt, wenn weder
 * DB-Passwort noch Management-Token verfügbar sind.
 *
 * Ein einziges Statement für alle [CatalogQuery]s: Ergebnis sind zwei Spalten (query_id, payload),
 * eine Zeile je Katalog-Zeile plus eine 'meta'-Zeile. Das Resultat wird im SQL-Editor als JSON
 * exportiert und landet unverändert in der Snapshot-Datei.
 *
 * Die 'meta'-Zeile trägt die Liste der exportierten query_ids. Nur dadurch lässt sich später
 * "Query lieferte 0 Zeilen" von "Query wurde gar nicht exportiert" unterscheiden.
 */
object SnapshotSql {

    const val SNAPSHOT_VERSION = 1
    const val META_QUERY_ID = "meta"

    fun build(config: SupabaseConfig): String {
        val profile = config.activeProfile ?: "unknown"
        val projectRef = config.projectRef ?: "unknown"

        val branches = CatalogQuery.entries.map { query ->
            // Bewusst ohne trimIndent auf dem zusammengesetzten Text: trimIndent würde die
            // Einrückung des eingebetteten SQL gegen die des Rahmens verrechnen.
            "-- ${query.id}: ${query.purpose}\n" +
                "SELECT ${literal(query.id)}::text AS query_id, to_jsonb(t) AS payload\n" +
                "FROM (\n" +
                query.statement().prependIndent("    ") + "\n" +
                ") t"
        }

        return buildString {
            appendLine(header(config, profile, projectRef))
            appendLine()
            appendLine(metaBranch(profile, projectRef))
            branches.forEach {
                appendLine()
                appendLine("UNION ALL")
                appendLine()
                appendLine(it)
            }
            append(";")
        }
    }

    private fun header(config: SupabaseConfig, profile: String, projectRef: String): String = """
        -- ===========================================================================
        -- PccSecurityCheckLovableStack — Katalog-Snapshot
        -- Profil:  $profile
        -- Projekt: $projectRef
        --
        -- ANLEITUNG
        --   1. Dieses Statement im Supabase-Dashboard unter "SQL Editor" ausfuehren.
        --   2. Ergebnis als JSON exportieren (Download-/Export-Menue am Ergebnis-Grid).
        --   3. Datei ablegen als:
        --        ${config.snapshotPath}
        --   4. Lauf starten: ACTIVE_PROFILE=$profile mvn -q compile exec:java
        --
        -- Das Statement ist reines SELECT auf pg_catalog/system-Views. Es legt nichts an,
        -- aendert nichts und loescht nichts. Gefahrlos auf Produktion ausfuehrbar.
        -- ===========================================================================
    """.trimIndent()

    private fun metaBranch(profile: String, projectRef: String): String {
        val queryIds = CatalogQuery.entries.joinToString(", ") { literal(it.id) }
        return """
            SELECT ${literal(META_QUERY_ID)}::text AS query_id,
                   jsonb_build_object(
                       'snapshot_version', $SNAPSHOT_VERSION,
                       'profile',          ${literal(profile)},
                       'project_ref',      ${literal(projectRef)},
                       'queries',          jsonb_build_array($queryIds),
                       'captured_at',      to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                       'database',         current_database(),
                       'server_version',   current_setting('server_version')
                   ) AS payload
        """.trimIndent()
    }

    /** Postgres-String-Literal mit verdoppelten Hochkommata. */
    private fun literal(value: String): String = "'" + value.replace("'", "''") + "'"
}

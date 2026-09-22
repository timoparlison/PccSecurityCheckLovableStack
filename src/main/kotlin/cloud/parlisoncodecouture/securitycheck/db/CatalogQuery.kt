package cloud.parlisoncodecouture.securitycheck.db

/**
 * Zentrale Registry aller Katalog-Abfragen.
 *
 * Das SQL steht bewusst NICHT mehr in den Checks: es muss aus drei Richtungen identisch nutzbar
 * sein — JDBC, Management-API und als exportiertes Statement, das jemand manuell im SQL-Editor
 * ausführt. Ein Check referenziert nur noch die [CatalogQuery] und mappt die [Row]s.
 *
 * Alle Statements sind reine SELECTs auf pg_catalog/system-Views. Es wird nichts angelegt,
 * geändert oder gelöscht.
 */
enum class CatalogQuery(
    /** Stabiler Schlüssel — landet als `query_id` im Snapshot. Nicht umbenennen. */
    val id: String,
    /** Kurzbeschreibung für den generierten SQL-Export. */
    val purpose: String,
    val sql: String,
) {
    RELATIONS(
        id = "relations",
        purpose = "RLS-Status, Policy-Anzahl und API-Rechte je Relation im public-Schema",
        sql = """
            SELECT c.relname,
                   c.relkind::text                                            AS relkind,
                   c.relrowsecurity,
                   c.relforcerowsecurity,
                   (SELECT count(*) FROM pg_policy pol WHERE pol.polrelid = c.oid) AS policy_count,
                   c.reloptions,
                   has_any_column_privilege('anon', c.oid, 'SELECT')          AS anon_select,
                   has_any_column_privilege('anon', c.oid, 'INSERT')          AS anon_insert,
                   has_any_column_privilege('anon', c.oid, 'UPDATE')          AS anon_update,
                   has_table_privilege('anon', c.oid, 'DELETE')               AS anon_delete,
                   has_any_column_privilege('authenticated', c.oid, 'SELECT') AS auth_select,
                   has_any_column_privilege('authenticated', c.oid, 'INSERT') AS auth_insert,
                   has_any_column_privilege('authenticated', c.oid, 'UPDATE') AS auth_update,
                   has_table_privilege('authenticated', c.oid, 'DELETE')      AS auth_delete
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
            ORDER BY c.relname
        """,
    ),

    POLICIES(
        id = "policies",
        purpose = "RLS-Policies im public-Schema (USING / WITH CHECK / Rollen)",
        sql = """
            SELECT tablename, policyname, cmd, roles, qual, with_check
            FROM pg_policies
            WHERE schemaname = 'public'
            ORDER BY tablename, policyname
        """,
    ),

    STORAGE_OBJECT_POLICIES(
        id = "storage-object-policies",
        purpose = "RLS-Policies auf storage.objects",
        sql = """
            SELECT policyname, cmd, roles, qual, with_check
            FROM pg_policies
            WHERE schemaname = 'storage' AND tablename = 'objects'
            ORDER BY policyname
        """,
    ),

    FUNCTIONS(
        id = "functions",
        purpose = "Functions im public-Schema inkl. EXECUTE-Rechten, proconfig und Quelltext",
        // Nur prokind='f': Procedures sind über PostgREST nicht per RPC aufrufbar, Trigger-Functions
        // ebenfalls nicht. Functions, die zu einer Extension gehören, bleiben außen vor.
        sql = """
            SELECT p.proname,
                   pg_get_function_identity_arguments(p.oid)                 AS args,
                   p.prosecdef,
                   p.proconfig,
                   pg_get_userbyid(p.proowner)                               AS owner,
                   l.lanname,
                   has_function_privilege('anon', p.oid, 'EXECUTE')          AS anon_execute,
                   has_function_privilege('authenticated', p.oid, 'EXECUTE') AS auth_execute,
                   pg_get_functiondef(p.oid)                                 AS definition
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            JOIN pg_language  l ON l.oid = p.prolang
            WHERE n.nspname = 'public'
              AND p.prokind = 'f'
              AND p.prorettype NOT IN ('trigger'::regtype, 'event_trigger'::regtype)
              AND NOT EXISTS (
                  SELECT 1 FROM pg_depend d
                  WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
              )
            ORDER BY p.proname, args
        """,
    ),

    SECDEF_FUNCTIONS(
        id = "secdef-functions",
        purpose = "SECURITY DEFINER-Functions aller Schemas — Runtime-Overlay für den Migrations-Audit",
        sql = """
            SELECT n.nspname AS schema_name,
                   p.proname AS name,
                   p.proconfig
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE p.prosecdef = true
              AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
            ORDER BY n.nspname, p.proname
        """,
    ),
    ;

    /** Einzeilig eingerücktes SQL, wie es an die DB bzw. in den Export geht. */
    fun statement(): String = sql.trimIndent().trim()

    companion object {
        fun byId(id: String): CatalogQuery? = entries.firstOrNull { it.id == id }
    }
}

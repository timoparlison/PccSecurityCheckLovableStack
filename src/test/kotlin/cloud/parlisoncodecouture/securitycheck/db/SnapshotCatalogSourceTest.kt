package cloud.parlisoncodecouture.securitycheck.db

import cloud.parlisoncodecouture.securitycheck.config.SupabaseConfig
import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SnapshotCatalogSourceTest {

    private fun config(snapshot: Path, projectRef: String? = "abcdefghijklmnop", maxAgeDays: Long = 14) =
        SupabaseConfig(
            activeProfile = "TEST",
            url = "https://abcdefghijklmnop.supabase.co",
            anonKey = "anon",
            serviceRoleKey = "service",
            projectRef = projectRef,
            connectTimeoutSeconds = 10,
            requestTimeoutSeconds = 20,
            frontendUrl = null,
            functionsPath = null,
            migrationsPath = null,
            dbHost = null,
            dbPort = 5432,
            dbName = "postgres",
            dbUser = "postgres",
            dbPassword = null,
            managementApiToken = null,
            managementApiUrl = "https://api.supabase.com",
            catalogSource = CatalogSourceKind.SNAPSHOT,
            snapshotPath = snapshot,
            snapshotMaxAgeDays = maxAgeDays,
        )

    private fun write(json: String): Path {
        val file = Files.createTempFile("snapshot", ".json")
        Files.writeString(file, json)
        file.toFile().deleteOnExit()
        return file
    }

    private fun capturedAt(daysAgo: Long): String =
        Instant.now().minus(daysAgo, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS).toString()

    private fun snapshotJson(
        capturedAt: String = capturedAt(1),
        projectRef: String = "abcdefghijklmnop",
        queries: String = """"relations", "policies", "storage-object-policies", "functions", "secdef-functions"""",
        extraRows: String = "",
    ) = """
        [
          {"query_id": "meta", "payload": {
             "snapshot_version": 1, "profile": "TEST", "project_ref": "$projectRef",
             "queries": [$queries], "captured_at": "$capturedAt",
             "database": "postgres", "server_version": "15.8"}},
          {"query_id": "relations", "payload": {
             "relname": "invoices", "relkind": "r", "relrowsecurity": false,
             "relforcerowsecurity": false, "policy_count": 0, "reloptions": null,
             "anon_select": true, "anon_insert": false, "anon_update": false, "anon_delete": false,
             "auth_select": true, "auth_insert": true, "auth_update": false, "auth_delete": false}},
          {"query_id": "relations", "payload": {
             "relname": "invoice_summary", "relkind": "v", "relrowsecurity": false,
             "relforcerowsecurity": false, "policy_count": 0,
             "reloptions": ["security_invoker=true"],
             "anon_select": true, "anon_insert": false, "anon_update": false, "anon_delete": false,
             "auth_select": true, "auth_insert": false, "auth_update": false, "auth_delete": false}},
          {"query_id": "policies", "payload": {
             "tablename": "invoices", "policyname": "read_all", "cmd": "SELECT",
             "roles": ["anon", "authenticated"], "qual": "true", "with_check": null}}$extraRows
        ]
    """.trimIndent()

    @Test
    fun `parses rows, arrays and booleans from the SQL editor export`() {
        val source = SnapshotCatalogSource.load(config(write(snapshotJson())))

        val relations = source.query(CatalogQuery.RELATIONS)
        assertEquals(2, relations.size)
        assertEquals("invoices", relations[0].string("relname"))
        assertTrue(relations[0].boolean("anon_select"))
        assertEquals(false, relations[0].boolean("relrowsecurity"))
        assertEquals(0, relations[0].int("policy_count"))
        // NULL-Array darf nicht knallen, echtes Array muss durchkommen.
        assertEquals(emptyList(), relations[0].textArray("reloptions"))
        assertEquals(listOf("security_invoker=true"), relations[1].textArray("reloptions"))

        val policies = source.query(CatalogQuery.POLICIES)
        assertEquals(listOf("anon", "authenticated"), policies[0].textArray("roles"))
        assertEquals("true", policies[0].string("qual"))
        assertEquals(null, policies[0].string("with_check"))
    }

    @Test
    fun `query exported but empty is not an error`() {
        val source = SnapshotCatalogSource.load(config(write(snapshotJson())))
        assertEquals(emptyList(), source.query(CatalogQuery.FUNCTIONS))
    }

    @Test
    fun `query missing from the export is reported instead of silently empty`() {
        val partial = snapshotJson(queries = """"relations", "policies"""")
        val source = SnapshotCatalogSource.load(config(write(partial)))
        assertFailsWith<CatalogQueryMissingException> { source.query(CatalogQuery.FUNCTIONS) }
        assertTrue(source.warnings.any { it.contains("fehlen") })
    }

    @Test
    fun `snapshot of a different project aborts the run`() {
        val foreign = snapshotJson(projectRef = "zzzzzzzzzzzzzzzz")
        val ex = assertFailsWith<SnapshotMismatchException> {
            SnapshotCatalogSource.load(config(write(foreign)))
        }
        assertTrue(ex.message!!.contains("zzzzzzzzzzzzzzzz"))
    }

    @Test
    fun `stale snapshot is usable but flagged`() {
        val source = SnapshotCatalogSource.load(config(write(snapshotJson(capturedAt = capturedAt(30)))))
        assertEquals(2, source.query(CatalogQuery.RELATIONS).size)
        assertTrue(source.warnings.any { it.contains("Tage alt") }, "erwartet Alters-Warnung, war: ${source.warnings}")
    }

    @Test
    fun `accepts wrapper object and payload delivered as a JSON string`() {
        val wrapped = """
            {"rows": [
              {"query_id": "meta", "payload": "{\"project_ref\": \"abcdefghijklmnop\", \"queries\": [\"relations\"]}"},
              {"query_id": "relations", "payload": "{\"relname\": \"notes\", \"relkind\": \"r\", \"anon_select\": \"t\"}"}
            ]}
        """.trimIndent()
        val source = SnapshotCatalogSource.load(config(write(wrapped)))
        val rows = source.query(CatalogQuery.RELATIONS)
        assertEquals("notes", rows[0].string("relname"))
        // Postgres-Boolean-Kurzform 't' muss als true ankommen.
        assertTrue(rows[0].boolean("anon_select"))
    }

    @Test
    fun `missing file explains how to create one`() {
        val missing = Files.createTempDirectory("snap").resolve("nope.json")
        val ex = assertFailsWith<SnapshotNotFoundException> { SnapshotCatalogSource.load(config(missing)) }
        assertTrue(ex.message!!.contains("sql-export"))
    }
}

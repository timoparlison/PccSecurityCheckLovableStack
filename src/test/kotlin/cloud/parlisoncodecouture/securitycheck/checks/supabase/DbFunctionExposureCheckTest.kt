package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.checks.supabase.DbFunctionExposureCheck.LiveFunction
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DbFunctionExposureCheckTest {

    private fun fn(
        anon: Boolean = false,
        auth: Boolean = false,
        searchPath: Boolean = true,
        body: String = "BEGIN RETURN 1; END",
    ) = LiveFunction(
        name = "get_invoices",
        identityArgs = "p_user_id uuid",
        securityDefiner = true,
        proconfig = if (searchPath) listOf("search_path=") else emptyList(),
        owner = "postgres",
        language = "plpgsql",
        anonExecute = anon,
        authenticatedExecute = auth,
        definition = "CREATE OR REPLACE FUNCTION public.get_invoices(p_user_id uuid) AS \$\$ $body \$\$",
    )

    private fun evaluate(f: LiveFunction) = DbFunctionExposureCheck.evaluateSecdef(f, null, migrationsScanned = false)

    @Test
    fun `anon callable without auth check is red and suggests revoke from public`() {
        val finding = evaluate(fn(anon = true, auth = true))
        assertEquals(CheckStatus.RED, finding.severity)
        assertTrue("FROM PUBLIC, anon" in finding.detail)
    }

    @Test
    fun `anon callable with auth check is yellow`() {
        val finding = evaluate(fn(anon = true, auth = true, body = "BEGIN IF auth.uid() IS NULL THEN RAISE; END IF; END"))
        assertEquals(CheckStatus.YELLOW, finding.severity)
    }

    @Test
    fun `commented out auth check does not count`() {
        val finding = evaluate(fn(anon = true, body = "BEGIN -- TODO auth.uid()\n RETURN 1; END"))
        assertEquals(CheckStatus.RED, finding.severity)
    }

    @Test
    fun `authenticated only without auth check is yellow`() {
        assertEquals(CheckStatus.YELLOW, evaluate(fn(auth = true)).severity)
    }

    @Test
    fun `missing search path is red when exposed and yellow when not`() {
        val body = "BEGIN PERFORM auth.uid(); END"
        assertEquals(CheckStatus.RED, evaluate(fn(auth = true, searchPath = false, body = body)).severity)
        assertEquals(CheckStatus.YELLOW, evaluate(fn(searchPath = false, body = body)).severity)
    }

    @Test
    fun `service role only with pinned search path is green`() {
        assertEquals(CheckStatus.GREEN, evaluate(fn()).severity)
    }

    @Test
    fun `dynamic sql via concatenation is red when exposed`() {
        val finding = evaluate(fn(auth = true, body = "BEGIN PERFORM auth.uid(); EXECUTE 'SELECT * FROM ' || tbl; END"))
        assertEquals(CheckStatus.RED, finding.severity)
        assertTrue("USING" in finding.detail)
    }
}

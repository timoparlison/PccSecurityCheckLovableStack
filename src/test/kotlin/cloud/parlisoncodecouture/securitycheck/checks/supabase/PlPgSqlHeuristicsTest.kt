package cloud.parlisoncodecouture.securitycheck.checks.supabase

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PlPgSqlHeuristicsTest {

    private fun startsInLiteral(sql: String) =
        PlPgSqlHeuristics.startsInsideStringLiteral(sql, sql.indexOf("CREATE OR REPLACE FUNCTION"))

    @Test
    fun `create function inside execute format literal is recognized`() {
        val sql = "DO \$x\$ BEGIN\n  EXECUTE format(\n    'CREATE OR REPLACE FUNCTION public.f(p uuid) '\n" +
            "    || 'RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS %L', v_src);\nEND; \$x\$;"
        assertTrue(startsInLiteral(sql))
    }

    @Test
    fun `plain create function is not a literal`() {
        assertFalse(startsInLiteral("-- neu\nCREATE OR REPLACE FUNCTION public.f() RETURNS void AS \$\$ BEGIN END \$\$;"))
        assertFalse(startsInLiteral("CREATE OR REPLACE FUNCTION public.f() RETURNS void AS \$\$ BEGIN END \$\$;"))
    }
}

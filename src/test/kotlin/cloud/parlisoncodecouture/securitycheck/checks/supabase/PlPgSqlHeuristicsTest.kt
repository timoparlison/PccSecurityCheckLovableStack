package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.checks.supabase.PlPgSqlHeuristics.FunctionSource
import kotlin.test.Test
import kotlin.test.assertEquals
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

    private val fns = listOf(
        FunctionSource("user_org_id", hasNoArgs = true, returnsSimpleScalar = true,
            body = "SELECT organization_id FROM profiles WHERE user_id = auth.uid()"),
        FunctionSource("has_full_access", hasNoArgs = true, returnsSimpleScalar = true,
            body = "SELECT EXISTS (SELECT 1 FROM roles WHERE org = user_org_id())"),
        FunctionSource("has_capability", hasNoArgs = false, returnsSimpleScalar = true,
            body = "SELECT has_full_access() OR p_cap = 'x'"),
        FunctionSource("list_cards", hasNoArgs = true, returnsSimpleScalar = false,
            body = "SELECT jsonb_agg(c) FROM cards c WHERE org = user_org_id()"),
    )

    @Test
    fun `only parameterless scalar helpers become guards, transitively`() {
        assertEquals(setOf("user_org_id", "has_full_access"), PlPgSqlHeuristics.guardFunctions(fns))
    }

    @Test
    fun `simple scalar return types are recognized`() {
        assertTrue(PlPgSqlHeuristics.returnsSimpleScalar("RETURNS boolean LANGUAGE sql"))
        assertTrue(PlPgSqlHeuristics.returnsSimpleScalar("RETURNS SETOF uuid LANGUAGE sql"))
        assertTrue(PlPgSqlHeuristics.returnsSimpleScalar("RETURNS TABLE(customer_id uuid) LANGUAGE sql"))
        assertFalse(PlPgSqlHeuristics.returnsSimpleScalar("RETURNS jsonb LANGUAGE sql"))
        assertFalse(PlPgSqlHeuristics.returnsSimpleScalar("RETURNS TABLE(id uuid, name text) LANGUAGE sql"))
    }

    @Test
    fun `call of a project guard counts as auth check, commented out call does not`() {
        val guards = PlPgSqlHeuristics.guardFunctions(fns)
        assertTrue(PlPgSqlHeuristics.hasAuthOrRoleCheck("IF p_org <> public.user_org_id() THEN RAISE", guards))
        assertFalse(PlPgSqlHeuristics.hasAuthOrRoleCheck("-- user_org_id()\nPERFORM list_cards()", guards))
        assertFalse(PlPgSqlHeuristics.hasAuthOrRoleCheck("IF p_org <> user_org_id() THEN RAISE"))
    }
}

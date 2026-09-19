package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.checks.supabase.RlsStatusCheck.Kind
import cloud.parlisoncodecouture.securitycheck.checks.supabase.RlsStatusCheck.Privileges
import cloud.parlisoncodecouture.securitycheck.checks.supabase.RlsStatusCheck.Relation
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import kotlin.test.Test
import kotlin.test.assertEquals

class RlsStatusCheckTest {

    private val none = Privileges(select = false, insert = false, update = false, delete = false)
    private val all = Privileges(select = true, insert = true, update = true, delete = true)
    private val readOnly = Privileges(select = true, insert = false, update = false, delete = false)

    private fun rel(
        kind: Kind = Kind.TABLE,
        rls: Boolean = true,
        policies: Int = 1,
        options: List<String> = emptyList(),
        anon: Privileges = none,
        auth: Privileges = none,
    ) = Relation("things", kind, rls, false, policies, options, anon, auth)

    private fun severity(r: Relation) = RlsStatusCheck.evaluate(r).severity

    @Test
    fun `table without rls is red only when roles have privileges`() {
        assertEquals(CheckStatus.RED, severity(rel(rls = false, anon = all, auth = all)))
        assertEquals(CheckStatus.RED, severity(rel(rls = false, auth = readOnly)))
        assertEquals(CheckStatus.YELLOW, severity(rel(rls = false)))
    }

    @Test
    fun `table with rls and policies is green, without policies yellow`() {
        assertEquals(CheckStatus.GREEN, severity(rel(anon = all)))
        assertEquals(CheckStatus.YELLOW, severity(rel(policies = 0, anon = all)))
    }

    @Test
    fun `view without security_invoker bypasses rls`() {
        assertEquals(CheckStatus.RED, severity(rel(kind = Kind.VIEW, anon = readOnly, auth = readOnly)))
        assertEquals(CheckStatus.YELLOW, severity(rel(kind = Kind.VIEW, auth = readOnly)))
        assertEquals(CheckStatus.GREEN, severity(rel(kind = Kind.VIEW)))
    }

    @Test
    fun `view with security_invoker is green in all spellings`() {
        for (opt in listOf("security_invoker=true", "security_invoker=on", "security_invoker=1", "SECURITY_INVOKER=TRUE")) {
            assertEquals(CheckStatus.GREEN, severity(rel(kind = Kind.VIEW, options = listOf(opt), anon = readOnly)), opt)
        }
        assertEquals(CheckStatus.RED, severity(rel(kind = Kind.VIEW, options = listOf("security_invoker=false"), anon = readOnly)))
    }

    @Test
    fun `materialized view readable by anon is red`() {
        assertEquals(CheckStatus.RED, severity(rel(kind = Kind.MATVIEW, rls = false, anon = readOnly)))
        assertEquals(CheckStatus.GREEN, severity(rel(kind = Kind.MATVIEW, rls = false)))
    }
}

package cloud.parlisoncodecouture.securitycheck.checks.supabase

import cloud.parlisoncodecouture.securitycheck.checks.supabase.PermissivePoliciesCheck.Policy
import cloud.parlisoncodecouture.securitycheck.core.CheckStatus
import kotlin.test.Test
import kotlin.test.assertEquals

class PermissivePoliciesCheckTest {

    private fun severity(roles: List<String>, cmd: String = "ALL") =
        PermissivePoliciesCheck.evaluate(Policy("things", "p", cmd, roles, "true", "true")).severity

    @Test
    fun `using true for service_role only is harmless`() {
        assertEquals(CheckStatus.GREEN, severity(listOf("service_role")))
    }

    @Test
    fun `using true for anon, authenticated or public stays red`() {
        assertEquals(CheckStatus.RED, severity(listOf("anon")))
        assertEquals(CheckStatus.RED, severity(emptyList()))
        assertEquals(CheckStatus.RED, severity(listOf("authenticated"), cmd = "UPDATE"))
        assertEquals(CheckStatus.RED, severity(listOf("service_role", "authenticated"), cmd = "UPDATE"))
    }
}

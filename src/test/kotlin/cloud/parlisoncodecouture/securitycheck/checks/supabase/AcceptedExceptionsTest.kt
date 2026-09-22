package cloud.parlisoncodecouture.securitycheck.checks.supabase

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AcceptedExceptionsTest {

    @Test
    fun `test code is recognized by directory or file name`() {
        assertTrue(EdgeFunctionAuditCheck.isTestFile("_shared/__tests__/fernauErrors_test.ts"))
        assertTrue(EdgeFunctionAuditCheck.isTestFile("create-user/index.test.ts"))
        assertTrue(EdgeFunctionAuditCheck.isTestFile("tests/cors.ts"))
        assertFalse(EdgeFunctionAuditCheck.isTestFile("create-user/index.ts"))
        assertFalse(EdgeFunctionAuditCheck.isTestFile("latest-report/index.ts"))
    }

    @Test
    fun `only hosted supabase counts as platform`() {
        assertTrue(ApiHttpHardeningCheck.isPlatformHosted("https://jcbjbebvwrtqrskzpxvp.supabase.co"))
        assertFalse(ApiHttpHardeningCheck.isPlatformHosted("https://api.example.com"))
        assertFalse(ApiHttpHardeningCheck.isPlatformHosted("https://supabase.co.evil.example"))
    }
}

-- ===========================================================================
-- PccSecurityCheckLovableStack — Setup SQL
-- ===========================================================================
-- Run this once in your Supabase project (Dashboard > SQL Editor) to enable
-- the catalog-based checks (RLS-Status, Permissive Policies).
--
-- These functions are SECURITY DEFINER and only callable by the service_role.
-- They read pg_catalog tables and return aggregated metadata — they do NOT
-- expose user data and they do NOT modify anything.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- security_check_rls_status:
--   For every base table in 'public': RLS-enabled flag and policy count.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.security_check_rls_status()
RETURNS TABLE(
    schema_name text,
    table_name  text,
    rls_enabled boolean,
    policy_count int
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT
        n.nspname::text AS schema_name,
        c.relname::text AS table_name,
        c.relrowsecurity AS rls_enabled,
        (SELECT count(*)::int FROM pg_policy WHERE polrelid = c.oid) AS policy_count
    FROM pg_class c
    JOIN pg_namespace n ON c.relnamespace = n.oid
    WHERE c.relkind = 'r'
      AND n.nspname = 'public'
    ORDER BY c.relname;
$$;

REVOKE EXECUTE ON FUNCTION public.security_check_rls_status() FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION public.security_check_rls_status() TO service_role;

-- ---------------------------------------------------------------------------
-- security_check_policies:
--   All policies in 'public' with their USING / WITH CHECK expressions
--   and the roles they apply to. Used for the permissive-policy heuristic.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.security_check_policies()
RETURNS TABLE(
    schema_name text,
    table_name  text,
    policy_name text,
    cmd         text,
    roles       text[],
    qual        text,
    with_check  text,
    permissive  text
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
    SELECT
        schemaname::text,
        tablename::text,
        policyname::text,
        cmd::text,
        roles::text[],
        qual::text,
        with_check::text,
        permissive::text
    FROM pg_policies
    WHERE schemaname = 'public'
    ORDER BY tablename, policyname;
$$;

REVOKE EXECUTE ON FUNCTION public.security_check_policies() FROM PUBLIC, anon, authenticated;
GRANT  EXECUTE ON FUNCTION public.security_check_policies() TO service_role;

-- ===========================================================================
-- Verify install:
--   SELECT * FROM public.security_check_rls_status();
--   SELECT * FROM public.security_check_policies();
-- ===========================================================================

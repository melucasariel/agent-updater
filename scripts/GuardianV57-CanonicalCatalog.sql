-- Guardian V5.7: canonical PostgreSQL catalog rows for SHA256 source vs restored lab.
-- READ ONLY. Run from psql with -X -qAt -v ON_ERROR_STOP=1 -v schema=fixture.
-- Redirect output to a PRIVATE local file, never stdout/logs in actual backups.
-- Comparison of catalog semantics, not row data, secrets, global role membership or app services.
BEGIN TRANSACTION READ ONLY;
WITH target AS (
  SELECT oid, nspname, nspowner, nspacl FROM pg_namespace WHERE nspname = :'schema'
), facts AS (
 SELECT 'SCHEMA|' || t.nspname || '|' || pg_get_userbyid(t.nspowner) AS fact
 FROM target t
 UNION ALL
 SELECT 'SCHEMA_ACL|' || COALESCE(
   (SELECT string_agg(
     CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END
     ||':'||x.privilege_type||':'||x.is_grantable::text||':'||pg_get_userbyid(x.grantor),
     ',' ORDER BY x.grantee,x.privilege_type,x.is_grantable,x.grantor
    ) FROM aclexplode(t.nspacl) x),'NONE')
 FROM target t
 UNION ALL
 SELECT 'TABLE|'||c.relname||'|'||c.relkind::text||'|'||pg_get_userbyid(c.relowner)||'|'||
        c.relrowsecurity::text||'|'||c.relforcerowsecurity::text
 FROM pg_class c JOIN target n ON n.oid=c.relnamespace
 WHERE c.relkind IN ('r','p','v','m','S','f')
 UNION ALL
 SELECT 'COLUMN|'||c.relname||'|'||a.attnum::text||'|'||a.attname||'|'||
        format_type(a.atttypid,a.atttypmod)||'|'||a.attnotnull::text||'|'||
        COALESCE(pg_get_expr(d.adbin,d.adrelid),'NONE')
 FROM pg_attribute a
 JOIN pg_class c ON c.oid=a.attrelid
 JOIN target n ON n.oid=c.relnamespace
 LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
 WHERE a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p','v','m','f')
 UNION ALL
 SELECT 'TABLE_ACL|'||c.relname||'|'||
  COALESCE((SELECT string_agg(
    CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END
    ||':'||x.privilege_type||':'||x.is_grantable::text||':'||pg_get_userbyid(x.grantor),
    ',' ORDER BY x.grantee,x.privilege_type,x.is_grantable,x.grantor
   ) FROM aclexplode(c.relacl) x),'NONE')
 FROM pg_class c JOIN target n ON n.oid=c.relnamespace
 WHERE c.relkind IN ('r','p','v','m','S','f')
 UNION ALL
 SELECT 'INDEX|'||t.relname||'|'||i.relname||'|'||pg_get_indexdef(i.oid)
 FROM pg_class i
 JOIN pg_index x ON x.indexrelid=i.oid
 JOIN pg_class t ON t.oid=x.indrelid
 JOIN target n ON n.oid=t.relnamespace
 UNION ALL
 SELECT 'CONSTRAINT|'||c.conname||'|'||COALESCE(cl.relname,'SCHEMA')||'|'||
        pg_get_constraintdef(c.oid,true)
 FROM pg_constraint c
 LEFT JOIN pg_class cl ON cl.oid=c.conrelid
 JOIN target n ON n.oid=c.connamespace
 UNION ALL
 SELECT 'POLICY|'||c.relname||'|'||p.polname||'|'||p.polcmd::text||'|'||
        p.polpermissive::text||'|'||
        COALESCE(pg_get_expr(p.polqual,p.polrelid),'NONE')||'|'||
        COALESCE(pg_get_expr(p.polwithcheck,p.polrelid),'NONE')||'|'||
        (SELECT string_agg(CASE WHEN y.oid=0 THEN 'PUBLIC' ELSE pg_get_userbyid(y.oid) END,
                           ',' ORDER BY CASE WHEN y.oid=0 THEN 'PUBLIC' ELSE pg_get_userbyid(y.oid) END)
         FROM unnest(p.polroles) AS y(oid))
 FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN target n ON n.oid=c.relnamespace
 UNION ALL
 SELECT 'DEFAULT_ACL|'||pg_get_userbyid(a.defaclrole)||'|'||a.defaclobjtype::text||'|'||
  COALESCE((SELECT string_agg(
    CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END
    ||':'||x.privilege_type||':'||x.is_grantable::text||':'||pg_get_userbyid(x.grantor),
    ',' ORDER BY x.grantee,x.privilege_type,x.is_grantable,x.grantor)
   FROM aclexplode(a.defaclacl) x),'NONE')
 FROM pg_default_acl a JOIN target n ON n.oid=a.defaclnamespace
 UNION ALL
 SELECT 'FUNCTION|'||p.proname||'|'||pg_get_function_identity_arguments(p.oid)||'|'||
        pg_get_userbyid(p.proowner)||'|'||p.prosecdef::text||'|'||
        encode(convert_to(pg_get_functiondef(p.oid),'UTF8'),'hex')
 FROM pg_proc p JOIN target n ON n.oid=p.pronamespace
 UNION ALL
 SELECT 'TRIGGER|'||c.relname||'|'||t.tgname||'|'||pg_get_triggerdef(t.oid,true)
 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN target n ON n.oid=c.relnamespace
 WHERE NOT t.tgisinternal
)
SELECT fact FROM facts ORDER BY fact;
ROLLBACK;

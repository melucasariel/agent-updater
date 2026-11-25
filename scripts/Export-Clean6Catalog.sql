-- ROTA62 CLEAN6 read-only PostgreSQL catalog exporter.
-- Only execute in a verified disposable PG17 lab. Run through psql -X -qAt -v ON_ERROR_STOP=1.
-- This does not authenticate that the database is the restored archive.
BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
WITH
schemas AS MATERIALIZED (
  SELECT oid,nspname,nspowner,nspacl
  FROM pg_catalog.pg_namespace
  WHERE nspname <> 'information_schema'
    AND nspname !~ '^pg_'
),
relations AS MATERIALIZED (
  SELECT c.oid,c.relname,c.relkind,c.relowner,c.relacl,s.nspname
  FROM pg_catalog.pg_class c
  JOIN schemas s ON s.oid=c.relnamespace
  WHERE c.relkind IN ('r','p','v','m','S','f')
),
procedures AS MATERIALIZED (
  SELECT p.oid,p.proname,p.proowner,p.proacl,s.nspname
  FROM pg_catalog.pg_proc p
  JOIN schemas s ON s.oid=p.pronamespace
),
types AS MATERIALIZED (
  SELECT t.oid,t.typname,t.typowner,t.typacl,s.nspname
  FROM pg_catalog.pg_type t
  JOIN schemas s ON s.oid=t.typnamespace
  WHERE t.typtype IN ('b','d','e','r','m') AND t.typisdefined AND t.typrelid=0
),
owners AS (
  SELECT 'schema:'||quote_ident(nspname) AS id,pg_catalog.pg_get_userbyid(nspowner) AS owner FROM schemas
  UNION ALL
  SELECT 'relation:'||quote_ident(nspname)||'.'||quote_ident(relname),pg_catalog.pg_get_userbyid(relowner) FROM relations
  UNION ALL
  SELECT 'function:'||quote_ident(nspname)||'.'||p.oid::regprocedure::text,pg_catalog.pg_get_userbyid(proowner) FROM procedures p
  UNION ALL
  SELECT 'type:'||quote_ident(nspname)||'.'||quote_ident(typname),pg_catalog.pg_get_userbyid(typowner) FROM types
),
privileges AS (
  SELECT 'schema:'||quote_ident(s.nspname) AS id,grantee,privilege_type,grantor,is_grantable
  FROM schemas s
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(s.nspacl,pg_catalog.acldefault('n',s.nspowner)))
  UNION ALL
  SELECT 'relation:'||quote_ident(c.nspname)||'.'||quote_ident(c.relname),grantee,privilege_type,grantor,is_grantable
  FROM relations c
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault((CASE WHEN c.relkind='S' THEN 's' ELSE 'r' END)::"char",c.relowner)))
  UNION ALL
  SELECT 'function:'||quote_ident(p.nspname)||'.'||p.oid::regprocedure::text,grantee,privilege_type,grantor,is_grantable
  FROM procedures p
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(p.proacl,pg_catalog.acldefault('f',p.proowner)))
  UNION ALL
  SELECT 'type:'||quote_ident(t.nspname)||'.'||quote_ident(t.typname),grantee,privilege_type,grantor,is_grantable
  FROM types t
  CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(t.typacl,pg_catalog.acldefault('T',t.typowner)))
  UNION ALL
  SELECT 'defaultacl:'||quote_ident(pg_catalog.pg_get_userbyid(d.defaclrole))||':'||COALESCE(quote_ident(s.nspname),'GLOBAL')||':'||d.defaclobjtype::text,
         a.grantee,a.privilege_type,a.grantor,a.is_grantable
  FROM pg_catalog.pg_default_acl d
  LEFT JOIN schemas s ON s.oid=d.defaclnamespace
  CROSS JOIN LATERAL pg_catalog.aclexplode(d.defaclacl) a
  WHERE d.defaclnamespace=0 OR s.oid IS NOT NULL
),
acls AS (
  SELECT id,
         CASE WHEN grantee=0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(grantee) END AS grantee,
         privilege_type AS privilege,
         pg_catalog.pg_get_userbyid(grantor) AS grantor,
         is_grantable AS grantable
  FROM privileges
)
SELECT pg_catalog.json_build_object(
  'format','r62-clean6-semantic-v1',
  'owners',COALESCE((SELECT json_agg(json_build_object('id',id,'owner',owner) ORDER BY id) FROM owners),'[]'::json),
  'acls',COALESCE((SELECT json_agg(json_build_object('id',id,'grantee',grantee,'privilege',privilege,'grantor',grantor,'grantable',grantable) ORDER BY id,grantee,privilege,grantor,grantable) FROM acls),'[]'::json)
);
ROLLBACK;

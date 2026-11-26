#!/usr/bin/env node
// ROTA62 Guardian V5.5: fail-closed, OFFLINE restoration dependency plan
// from the already-sanitzed V5.4 report. No Docker, SQL, archive, password or network.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const expectedHeader='=== ROTA62 GUARDIAN V5.4 AUTHENTICATED PG_RESTORE CATALOG ===';
const requiredTrue=[
 'CIPHERTEXT_SHA256_MATCH','AES_GCM_TAG_AUTHENTICATED','LOCAL_PG17_IMAGE_VERIFIED',
 'DECRYPTED_PG_CUSTOM_HEADER','PG_RESTORE_CATALOG'
];
const requiredNo=['PG_RESTORE_EXECUTED_SQL','DATABASE_RESTORED','ROLES_ACL_RESTORED','PRODUCTION_TOUCHED'];
const requiredCounts=['ARCHIVE_CATALOG_ITEMS','TOC_TABLE','TOC_TABLE_DATA','TOC_EXTENSION',
 'TOC_FUNCTION','TOC_ACL','TOC_DEFAULT_ACL','TOC_POLICY','TOC_ROW_SECURITY','TOC_TRIGGER',
 'TOC_INDEX','EXPECTED_USER_TABLES_REFERENCE'];
const safeKey=/^[A-Z][A-Z0-9_]*$/;
const fail=c=>{throw Error(c);};
export function parseSafeReport(source){
 if(typeof source!=='string'||Buffer.byteLength(source,'utf8')>32768)fail('REPORT_SIZE_INVALID');
 const lines=source.replaceAll('\r\n','\n').trim().split('\n');
 if(lines[0]!==expectedHeader||lines.at(-1)!=='END_REPORT_OK')fail('REPORT_ENVELOPE_INVALID');
 const out=new Map();
 for(const line of lines.slice(1,-1)){
  const i=line.indexOf('=');
  if(i<=0||i===line.length-1)fail('REPORT_LINE_INVALID');
  const k=line.slice(0,i),v=line.slice(i+1);
  if(!safeKey.test(k)||!(/^[A-Z0-9_]+$/.test(v))||out.has(k))fail('REPORT_LINE_INVALID');
  if(!/^(TOC_[A-Z_]+|ARCHIVE_CATALOG_ITEMS|ARCHIVE_CONTENT_SHA16|EXPECTED_USER_TABLES_REFERENCE|CIPHERTEXT_SHA256_MATCH|AES_GCM_TAG_AUTHENTICATED|LOCAL_PG17_IMAGE_VERIFIED|DECRYPTED_PG_CUSTOM_HEADER|PG_RESTORE_CATALOG|CATALOG_COUNTS_DO_NOT_VALIDATE_DATA|PG_RESTORE_EXECUTED_SQL|DATABASE_RESTORED|ROLES_ACL_RESTORED|ARCHIVE_PLAINTEXT_FILE_WRITTEN|PRODUCTION_TOUCHED|RTO_4_TO_6_HOURS_PROVEN|DEPENDENCY_(?:VISIBLE_OWNER_ROLES|DISTINCT_EXTENSIONS|UNCLASSIFIED_TOC_ENTRIES|AMBIGUOUS_TOC_OWNER_ENTRIES|SHA16|ROLE_GRANTEES_COMPLETE)|SHAPE_(?:RECOGNIZED_TYPES|UNRECOGNIZED_TYPES|NO_OWNER_PROOF_ITEMS|OWNER_CANDIDATE_ONLY_ITEMS|NONSTANDARD_LAST_TOKENS|HISTORICAL_GLOBAL_ROLES_VERIFIED)|BLIND_(?:KNOWN_PUBLIC_KIND_ITEMS|OTHER_UNKNOWN_SHAPES|NONSTANDARD_CANDIDATE_ITEMS|NONSTANDARD_NO_PROOF_ITEMS|HISTORICAL_GLOBAL_ROLES_VERIFIED)|SCOPE_(?:PUBLIC_SCHEMA_TABLES|OTHER_SIMPLE_SCHEMA_TABLES|NO_SCHEMA_TABLES|COMPLEX_SCHEMA_TABLES|ORIGINAL_USER_TABLES_VALIDATED)|PAIR_(?:STRUCTURALLY_MATCHED|UNPAIRED_SIMPLE_TABLE|UNPAIRED_SIMPLE_DATA|AMBIGUOUS_TABLE|AMBIGUOUS_DATA|DUPLICATE_NONUNIQUE|ROWS_VERIFIED))$/.test(k))fail('UNKNOWN_REPORT_FIELD');
  out.set(k,v);
 }
 for(const k of requiredTrue)if(out.get(k)!=='YES'&&out.get(k)!=='PASS')fail('UNVERIFIED_AUTH_OR_CATALOG');
 for(const k of requiredNo)if(out.get(k)!=='NO')fail('UNEXPECTED_RESTORE_OR_PRODUCTION');
 if(out.get('ARCHIVE_PLAINTEXT_FILE_WRITTEN')!=='NO')fail('PLAINTEXT_PERSISTENCE_RISK');
 if(out.get('CATALOG_COUNTS_DO_NOT_VALIDATE_DATA')!=='YES')fail('REPORT_LIMIT_MISSING');
 if(out.get('RTO_4_TO_6_HOURS_PROVEN')!=='NO')fail('UNVERIFIED_RTO');
 if(!/^[A-F0-9]{16}$/.test(out.get('ARCHIVE_CONTENT_SHA16')||''))fail('FINGERPRINT_INVALID');
 for(const k of requiredCounts)if(!/^(?:0|[1-9][0-9]{0,7})$/.test(out.get(k)||''))fail('MISSING_OR_INVALID_COUNT');
 // V6.4 optional dependency metadata: never add to TOC object totals.
 // Old V5.4 reports remain valid and retain identical meanings.
 if(out.has('DEPENDENCY_SHA16')){
  if(!/^[A-F0-9]{16}$/.test(out.get('DEPENDENCY_SHA16')))fail('FINGERPRINT_INVALID');
  if(out.get('DEPENDENCY_ROLE_GRANTEES_COMPLETE')!=='NO')fail('REPORT_LIMIT_MISSING');
  for(const k of ['DEPENDENCY_VISIBLE_OWNER_ROLES','DEPENDENCY_DISTINCT_EXTENSIONS','DEPENDENCY_UNCLASSIFIED_TOC_ENTRIES','DEPENDENCY_AMBIGUOUS_TOC_OWNER_ENTRIES'])
   if(!/^(?:0|[1-9][0-9]{0,7})$/.test(out.get(k)||''))fail('MISSING_OR_INVALID_COUNT');
  if(Number(out.get('DEPENDENCY_DISTINCT_EXTENSIONS'))>Number(out.get('TOC_EXTENSION'))||
     Number(out.get('DEPENDENCY_UNCLASSIFIED_TOC_ENTRIES'))>Number(out.get('ARCHIVE_CATALOG_ITEMS'))||
     Number(out.get('DEPENDENCY_AMBIGUOUS_TOC_OWNER_ENTRIES'))>Number(out.get('ARCHIVE_CATALOG_ITEMS')))
   fail('DEPENDENCY_COUNTER_INCONSISTENT');
 }


 // V6.5 shape audit is OPTIONAL for historical V5.4/V6.4 reports.
 // Never sum these fields with TOC_ types and never infer verified roles.
 const shapeKeys=['SHAPE_RECOGNIZED_TYPES','SHAPE_UNRECOGNIZED_TYPES',
  'SHAPE_NO_OWNER_PROOF_ITEMS','SHAPE_OWNER_CANDIDATE_ONLY_ITEMS',
  'SHAPE_NONSTANDARD_LAST_TOKENS'];
 if(shapeKeys.some(k=>out.has(k))||out.has('SHAPE_HISTORICAL_GLOBAL_ROLES_VERIFIED')){
  if(shapeKeys.some(k=>!out.has(k))||
     out.get('SHAPE_HISTORICAL_GLOBAL_ROLES_VERIFIED')!=='NO')
   fail('SHAPE_REPORT_INCOMPLETE');
  for(const k of shapeKeys)
   if(!/^(?:0|[1-9][0-9]{0,7})$/.test(out.get(k)))fail('MISSING_OR_INVALID_COUNT');
  const rec=Number(out.get('SHAPE_RECOGNIZED_TYPES'));
  const unk=Number(out.get('SHAPE_UNRECOGNIZED_TYPES'));
  const noProof=Number(out.get('SHAPE_NO_OWNER_PROOF_ITEMS'));
  const candidate=Number(out.get('SHAPE_OWNER_CANDIDATE_ONLY_ITEMS'));
  const nonstandard=Number(out.get('SHAPE_NONSTANDARD_LAST_TOKENS'));
  if(rec+unk!==Number(out.get('ARCHIVE_CATALOG_ITEMS'))||
     noProof+candidate!==rec||nonstandard>rec)
   fail('SHAPE_COUNTER_INCONSISTENT');
 }


 // V6.6 fields are optional for legacy reports. Validate as a complete group.
 const blindKeys=['BLIND_KNOWN_PUBLIC_KIND_ITEMS','BLIND_OTHER_UNKNOWN_SHAPES',
  'BLIND_NONSTANDARD_CANDIDATE_ITEMS','BLIND_NONSTANDARD_NO_PROOF_ITEMS'];
 if(blindKeys.some(k=>out.has(k))||out.has('BLIND_HISTORICAL_GLOBAL_ROLES_VERIFIED')){
  if(blindKeys.some(k=>!out.has(k))||
    out.get('BLIND_HISTORICAL_GLOBAL_ROLES_VERIFIED')!=='NO'||
    !shapeKeys.every(k=>out.has(k)))fail('BLIND_REPORT_INCOMPLETE');
  for(const k of blindKeys)
   if(!/^(?:0|[1-9][0-9]{0,7})$/.test(out.get(k)))fail('MISSING_OR_INVALID_COUNT');
  if(Number(out.get('BLIND_KNOWN_PUBLIC_KIND_ITEMS'))+
     Number(out.get('BLIND_OTHER_UNKNOWN_SHAPES'))!==Number(out.get('SHAPE_UNRECOGNIZED_TYPES'))||
     Number(out.get('BLIND_NONSTANDARD_CANDIDATE_ITEMS'))+
     Number(out.get('BLIND_NONSTANDARD_NO_PROOF_ITEMS'))!==Number(out.get('SHAPE_NONSTANDARD_LAST_TOKENS')))
    fail('BLIND_COUNTER_INCONSISTENT');
 }

 // V6.7 optional TABLE scope counters, consistent with TOC_TABLE.
 const scopeKeys=['SCOPE_PUBLIC_SCHEMA_TABLES','SCOPE_OTHER_SIMPLE_SCHEMA_TABLES',
  'SCOPE_NO_SCHEMA_TABLES','SCOPE_COMPLEX_SCHEMA_TABLES'];
 if(scopeKeys.some(k=>out.has(k))||out.has('SCOPE_ORIGINAL_USER_TABLES_VALIDATED')){
  if(scopeKeys.some(k=>!out.has(k))||
    out.get('SCOPE_ORIGINAL_USER_TABLES_VALIDATED')!=='NO')
    fail('SCOPE_REPORT_INCOMPLETE');
  for(const k of scopeKeys)
   if(!/^(?:0|[1-9][0-9]{0,7})$/.test(out.get(k)))
    fail('MISSING_OR_INVALID_COUNT');
  if(scopeKeys.reduce((sum,k)=>sum+Number(out.get(k)),0)!==
    Number(out.get('TOC_TABLE')))fail('SCOPE_COUNTER_INCONSISTENT');
 }
 // V6.8 optional pairing counters: no identifier or data claims.
 const pairKeys=['PAIR_STRUCTURALLY_MATCHED','PAIR_UNPAIRED_SIMPLE_TABLE',
   'PAIR_UNPAIRED_SIMPLE_DATA','PAIR_AMBIGUOUS_TABLE',
   'PAIR_AMBIGUOUS_DATA','PAIR_DUPLICATE_NONUNIQUE'];
 if(pairKeys.some(k=>out.has(k))||out.has('PAIR_ROWS_VERIFIED')){
  if(pairKeys.some(k=>!out.has(k))||out.get('PAIR_ROWS_VERIFIED')!=='NO'||
     !scopeKeys.every(k=>out.has(k)))fail('PAIR_REPORT_INCOMPLETE');
  for(const k of pairKeys)
   if(!/^(?:0|[1-9][0-9]{0,7})$/.test(out.get(k)))
    fail('MISSING_OR_INVALID_COUNT');
  const p=k=>Number(out.get(k));
  if(p('PAIR_STRUCTURALLY_MATCHED')+p('PAIR_UNPAIRED_SIMPLE_TABLE')+
     p('PAIR_AMBIGUOUS_TABLE')!==Number(out.get('TOC_TABLE'))||
     p('PAIR_STRUCTURALLY_MATCHED')+p('PAIR_UNPAIRED_SIMPLE_DATA')+
     p('PAIR_AMBIGUOUS_DATA')!==Number(out.get('TOC_TABLE_DATA'))||
     p('PAIR_DUPLICATE_NONUNIQUE')>
      p('PAIR_UNPAIRED_SIMPLE_TABLE')+p('PAIR_UNPAIRED_SIMPLE_DATA'))
    fail('PAIR_COUNTER_INCONSISTENT');
 }
 const counts={};
 for(const [k,v] of out)if(k.startsWith('TOC_')){
  if(!/^(?:0|[1-9][0-9]{0,7})$/.test(v))fail('INVALID_TOC_COUNT');
  counts[k.slice(4)]=Number(v);
 }
 const actual=Object.values(counts).reduce((a,b)=>a+b,0);
 if(actual!==Number(out.get('ARCHIVE_CATALOG_ITEMS')))fail('TOC_TOTAL_INCONSISTENT');
 return {
  counts,items:actual,referenceTables:Number(out.get('EXPECTED_USER_TABLES_REFERENCE')),
  fingerprint:out.get('ARCHIVE_CONTENT_SHA16')
 };
}
export function readiness(parsed){
 const c=parsed.counts;
 const tableDelta=(c.TABLE??0)-parsed.referenceTables;
 const signal={
  rolesAndOwners:true,
  defaultPrivileges:(c.DEFAULT_ACL??0)>0,
  grantACLs:(c.ACL??0)>0,
  extensions:(c.EXTENSION??0)>0,
  triggers:(c.TRIGGER??0)>0,
  rowSecurity:(c.ROW_SECURITY??0)>0,
  policy:(c.POLICY??0)>0,
  tableData:(c.TABLE_DATA??0)>0,
  tableScopeReview:tableDelta!==0,
  unknownTocType:(c.OTHER??0)>0
 };
 // One TOC TABLE is not equivalent to a pg_class table in a specific schema.
 // TABLE DATA entries also are not a trustworthy proxy for row counts.
 const conditions=[
 'REQUIRE_OFFICIAL_GLOBAL_ROLES_DUMP',
 'REQUIRE_OWNER_ACL_DEFAULT_ACL_REPLAY_CHECK',
 'REQUIRE_EXTENSION_COMPATIBILITY_PREFLIGHT',
 'REQUIRE_TRIGGER_AND_CRON_NETWORK_ISOLATION',
 'REQUIRE_FUNCTION_AND_RLS_POSTCHECK',
 'REQUIRE_ORIGINAL_DATABASE_SCHEMA_SCOPE_COMPARISON',
 'REQUIRE_STORAGE_WEB_API_SECRETS_SEPARATE',
 'REQUIRE_OFFSITE_RECOVERY_KEY',
 'REQUIRE_TIMED_END_TO_END_REHEARSAL'
 ];
 if(signal.unknownTocType)conditions.push('REQUIRE_UNCLASSIFIED_TOC_REVIEW');
 return {counts:c,items:parsed.items,tableDelta,signal,conditions};
}
function run(argv){
 if(argv.length!==2||argv[0]!=='--safe-report'||!path.isAbsolute(argv[1]))fail('USAGE');
 const data=fs.readFileSync(argv[1],'utf8'),r=readiness(parseSafeReport(data));
 const lines=[
  '=== ROTA62 GUARDIAN V5.5 RECOVERY PRE-FLIGHT ===',
  'MODE=OFFLINE_SANITIZED_REPORT_ONLY',
  'CATALOG_REPORT_FIELDS_VALIDATED=YES',
  'REPORT_CRYPTOGRAPHIC_AUTHENTICITY=NOT_ATTESTED',
  'ARCHIVE_OBJECTS='+r.items,
  'TABLE_TOC_COUNT='+(r.counts.TABLE??0),
  'TABLE_DATA_TOC_COUNT='+(r.counts.TABLE_DATA??0),
  'REFERENCE_SCOPED_TABLE_COUNT='+((r.counts.TABLE??0)-r.tableDelta),
  'TABLE_COUNT_SCOPE_MISMATCH='+(r.signal.tableScopeReview?'REVIEW_REQUIRED':'NO'),
  'TABLE_DATA_IS_NOT_ROW_COUNT=YES',
  'TOC_ACL_ENTRIES='+(r.counts.ACL??0),
  'TOC_DEFAULT_ACL_ENTRIES='+(r.counts.DEFAULT_ACL??0),
  'TOC_TRIGGERS='+(r.counts.TRIGGER??0),
  'TOC_ROW_SECURITY_ENTRIES='+(r.counts.ROW_SECURITY??0),
  'TOC_UNCLASSIFIED_ITEMS='+(r.counts.OTHER??0),
  'RECOVERY_DEPENDENCY_CHECKS='+r.conditions.length];
 for(const name of r.conditions)lines.push('GATE_'+name+'=BLOCKED_PENDING_EVIDENCE');
 lines.push('DO_NOT_USE_NO_OWNER_OR_NO_PRIVILEGES=YES');
 lines.push('PRODUCTION_ORIGINAL_CONTAINERS_UNTOUCHED=YES');
 lines.push('NO_CIPHERTEXT_OR_PASSWORD_READ=YES');
 lines.push('NO_DOCKER_OR_SQL_EXECUTED=YES');
 lines.push('RTO_4_TO_6_HOURS_PROVEN=NO');
 lines.push('RECOVERY_READY=NO');
 lines.push('END_REPORT_OK');
 console.log(lines.join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{run(process.argv.slice(2));}
 catch(e){
  const known=new Set(['USAGE','REPORT_SIZE_INVALID','REPORT_ENVELOPE_INVALID','REPORT_LINE_INVALID','UNKNOWN_REPORT_FIELD',
   'UNVERIFIED_AUTH_OR_CATALOG','UNEXPECTED_RESTORE_OR_PRODUCTION','PLAINTEXT_PERSISTENCE_RISK',
   'REPORT_LIMIT_MISSING','UNVERIFIED_RTO','FINGERPRINT_INVALID','MISSING_OR_INVALID_COUNT','INVALID_TOC_COUNT',
   'TOC_TOTAL_INCONSISTENT','DEPENDENCY_COUNTER_INCONSISTENT']);
  console.log('=== ROTA62 GUARDIAN V5.5 RECOVERY PRE-FLIGHT ===\nSTATUS=BLOCKED_'+
   (known.has(e.message)?e.message:'REDACTED')+
   '\nNO_DOCKER_OR_SQL_EXECUTED=YES\nPRODUCTION_ORIGINAL_CONTAINERS_UNTOUCHED=YES\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

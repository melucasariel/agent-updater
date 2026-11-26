import assert from 'node:assert/strict';
import {parseSafeReport,readiness} from './GuardianV55-RecoveryPreflight.mjs';
// Synthetic, public-category totals only; no original TOC object names or user data.
const toc={
 ACL:210,COMMENT:41,CONSTRAINT:93,DEFAULT_ACL:27,EXTENSION:6,FK_CONSTRAINT:56,
 FUNCTION:87,INDEX:128,OTHER:13,POLICY:8,ROW_SECURITY:52,SCHEMA:8,
 SEQUENCE:3,SEQUENCE_OWNED_BY:2,SEQUENCE_SET:5,TABLE:77,TABLE_DATA:73,
 TRIGGER:15,TYPE:15
};
const begin='=== ROTA62 GUARDIAN V5.4 AUTHENTICATED PG_RESTORE CATALOG ===';
const lines=[begin,'CIPHERTEXT_SHA256_MATCH=YES','AES_GCM_TAG_AUTHENTICATED=YES',
 'LOCAL_PG17_IMAGE_VERIFIED=YES','DECRYPTED_PG_CUSTOM_HEADER=YES','PG_RESTORE_CATALOG=PASS',
 'ARCHIVE_CONTENT_SHA16=EA995E37864FF769','ARCHIVE_CATALOG_ITEMS=919',
 ...Object.entries(toc).map(([k,v])=>('TOC_'+k+'='+v)),
 'EXPECTED_USER_TABLES_REFERENCE=76',
 'CATALOG_COUNTS_DO_NOT_VALIDATE_DATA=YES','PG_RESTORE_EXECUTED_SQL=NO',
 'DATABASE_RESTORED=NO','ROLES_ACL_RESTORED=NO',
 'ARCHIVE_PLAINTEXT_FILE_WRITTEN=NO','PRODUCTION_TOUCHED=NO',
 'RTO_4_TO_6_HOURS_PROVEN=NO','END_REPORT_OK'];
const good=lines.join('\n')+'\n';
const extra=[
 'DEPENDENCY_VISIBLE_OWNER_ROLES=5',
 'DEPENDENCY_DISTINCT_EXTENSIONS=6',
 'DEPENDENCY_UNCLASSIFIED_TOC_ENTRIES=13',
 'DEPENDENCY_AMBIGUOUS_TOC_OWNER_ENTRIES=0',
 'DEPENDENCY_SHA16=EA995E37864FF769',
 'DEPENDENCY_ROLE_GRANTEES_COMPLETE=NO'
];
const enhanced=good.replace('END_REPORT_OK',extra.join('\n')+'\nEND_REPORT_OK');
assert.equal(parseSafeReport(enhanced).items,919);
assert.throws(()=>parseSafeReport(enhanced.replace('DEPENDENCY_DISTINCT_EXTENSIONS=6','DEPENDENCY_DISTINCT_EXTENSIONS=999')),e=>e.message==='DEPENDENCY_COUNTER_INCONSISTENT');
assert.equal(parseSafeReport(good).items,919);
assert.throws(()=>parseSafeReport(enhanced.replace('DEPENDENCY_ROLE_GRANTEES_COMPLETE=NO','DEPENDENCY_ROLE_GRANTEES_COMPLETE=YES')),e=>e.message==='REPORT_LIMIT_MISSING');
const p=parseSafeReport(good);
assert.equal(p.items,919);
assert.equal(p.counts.TABLE,77);
assert.equal(p.counts.TABLE_DATA,73);
assert.equal(p.referenceTables,76);
const r=readiness(p);
assert.equal(r.tableDelta,1);
assert.equal(r.signal.tableScopeReview,true);
assert.equal(r.signal.defaultPrivileges,true);
assert.equal(r.signal.unknownTocType,true);
assert.ok(r.conditions.includes('REQUIRE_OFFICIAL_GLOBAL_ROLES_DUMP'));
assert.ok(r.conditions.includes('REQUIRE_OWNER_ACL_DEFAULT_ACL_REPLAY_CHECK'));
assert.ok(r.conditions.includes('REQUIRE_UNCLASSIFIED_TOC_REVIEW'));
const invalid=(src,from,to)=>src.replace(from,to);
const bad=[
 [invalid(good,'AES_GCM_TAG_AUTHENTICATED=YES','AES_GCM_TAG_AUTHENTICATED=NO'),'UNVERIFIED_AUTH_OR_CATALOG'],
 [invalid(good,'ARCHIVE_CATALOG_ITEMS=919','ARCHIVE_CATALOG_ITEMS=918'),'TOC_TOTAL_INCONSISTENT'],
 [invalid(good,'PRODUCTION_TOUCHED=NO','PRODUCTION_TOUCHED=YES'),'UNEXPECTED_RESTORE_OR_PRODUCTION'],
 [invalid(good,'TOC_DEFAULT_ACL=27','TOC_DEFAULT_ACL=ABC'),'MISSING_OR_INVALID_COUNT'],
 [invalid(good,'END_REPORT_OK','END_REPORT_FAIL'),'REPORT_ENVELOPE_INVALID'],
 [invalid(good,'TOC_INDEX=128','TOC_INDEX=128\nTOC_INDEX=128'),'REPORT_LINE_INVALID'],
 [invalid(good,'ARCHIVE_CONTENT_SHA16=EA995E37864FF769','ARCHIVE_CONTENT_SHA16=INVALID'),'FINGERPRINT_INVALID'],
 [invalid(good,'TOC_TABLE=77','TOC_TABLE=78'),'TOC_TOTAL_INCONSISTENT']
];
for(const [txt,code] of bad)assert.throws(()=>parseSafeReport(txt),e=>e.message===code,'Expected '+code);
console.log('V55_AUTHENTICATED_REPORT_STRICT_PARSE=PASS');
console.log('V55_TABLE_SCOPE_77_VS_76_REQUIRES_REVIEW=PASS');
console.log('V55_UNCLASSIFIED_ROLES_ACL_TRIGGER_REQUIRE_GATES=PASS');
console.log('V55_CORRUPT_REPLAY_OR_PRODUCTION_FLAG_REJECTED=PASS');
console.log('V55_SENSITIVE_SOURCE_NAMES_OR_DATA_USED=NO');

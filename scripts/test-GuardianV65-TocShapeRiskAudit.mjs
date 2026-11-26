import assert from 'node:assert/strict';
import {auditTocShape} from './GuardianV65-TocShapeRiskAudit.mjs';
const entries=[
 '1; 2615 100 SCHEMA - public postgres',
 '2; 0 0 EXTENSION - pgcrypto   ',
 '3; 0 0 EXTENSION - pg_net\t',
 '4; 1259 100 TABLE public rides postgres',
 '5; 0 100 TABLE DATA public rides postgres',
 '6; 0 100 ACL public TABLE rides postgres',
 '7; 0 100 DEFAULT ACL public DEFAULT PRIVILEGES FOR TABLES postgres',
 '8; 0 100 COMMENT - TABLE rides postgres',
 '9; 0 100 MYSTERY ENTRY payload ownerlike',
 '10; 0 100 FUNCTION public \"quoted role\"'
].join('\n');
const a=auditTocShape(entries);
assert.equal(a.entries,10);
assert.equal(a.extensionEntries,2);
assert.equal(a.unrecognizedTypes,1);
assert.equal(a.recognizedTypes,9);
assert.equal(a.typesWithoutOwnerProof,6);
assert.equal(a.structuralOwnerCandidatesOnly,3);
assert.equal(a.nonstandardLastTokens,1);
assert.equal(a.verifiedHistoricalGlobalRoles,0);
assert.equal(a.rolesAndAclRestoreReady,false);
assert.equal(a.sqlExecuted,false);
assert.equal(a.productionTouched,false);
assert.throws(()=>auditTocShape(entries.replace('10; 0 100','9; 0 100')),e=>e.message==='TOC_DUPLICATE_ID');
assert.throws(()=>auditTocShape(entries.replace('EXTENSION - pgcrypto   ','EXTENSION - pgcrypto bad owner')),e=>e.message==='EXTENSION_TOC_FORMAT_UNSUPPORTED');
assert.throws(()=>auditTocShape('1; 0 1 TABLE public a postgres'),e=>e.message==='TOC_ITEMS_INVALID');
assert.equal(auditTocShape(entries.replace('TABLE public rides postgres','TABLE public ownerlike ownerlike')).verifiedHistoricalGlobalRoles,0);
console.log('V65_NO_FALSE_VERIFIED_OWNER_INFERENCE=PASS');
console.log('V65_UNKNOWN_AND_QUOTED_TOC_SHAPES_VISIBLE_AS_COUNTS=PASS');
console.log('V65_UNKNOWN_EXTENSION_FORMAT_FAIL_CLOSED=PASS');
console.log('V65_NO_SQL_PRODUCTION_UNTOUCHED=YES');

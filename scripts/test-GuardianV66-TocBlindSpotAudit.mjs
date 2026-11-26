import assert from 'node:assert/strict';
import {auditTocBlindSpots} from './GuardianV66-TocBlindSpotAudit.mjs';
const toc=[
 '1; 1 1 SCHEMA - public postgres',
 '2; 1 1 EXTENSION - pgcrypto   ',
 '3; 1 1 STATISTICS DATA public stats_private postgres',
 '4; 1 1 EVENT TRIGGER - event_private postgres',
 '5; 1 1 MYSTERY private_account rolelike',
 '6; 1 1 FUNCTION public function_private \"quoted owner\"',
 '7; 1 1 ACL public TABLE private_table \"quoted owner\"'
].join('\n');
const r=auditTocBlindSpots(toc);
assert.equal(r.entries,7);
assert.equal(r.v65Unrecognized,3);
assert.equal(r.recognizedPublicPgKindsNotInV65,2);
assert.equal(r.otherUnknownShapes,1);
assert.deepEqual(r.publicKindHistogram,{'STATISTICS DATA':1,'EVENT TRIGGER':1});
assert.equal(r.v65NonstandardLastTokens,2);
assert.equal(r.nonstandardInCandidateOnlyTypes,1);
assert.equal(r.nonstandardInNoOwnerProofTypes,1);
assert.equal(r.historicalRolesVerified,false);
assert.equal(r.restoreReady,false);
assert.equal(r.sqlExecuted,false);
const serialized=JSON.stringify(r);
for(const forbidden of ['private_account','rolelike','stats_private','event_private','private_table','function_private','quoted owner'])
 assert.equal(serialized.includes(forbidden),false,'Private identifier leaked');
assert.throws(()=>auditTocBlindSpots(toc.replace('7; 1 1','6; 1 1')),e=>e.message==='TOC_DUPLICATE_ID');
assert.throws(()=>auditTocBlindSpots('1; 1 1 TABLE a b c'),e=>e.message==='TOC_ITEMS_INVALID');
console.log('V66_KNOWN_STANDARD_KIND_HISTOGRAM_REDACTED=PASS');
console.log('V66_UNKNOWN_AND_AMBIGUITY_TOTALS=PASS');
console.log('V66_PRIVATE_IDENTIFIERS_NEVER_PRINTED=PASS');
console.log('V66_NO_HISTORICAL_ROLES_OR_RESTORE_AUTHORIZATION=PASS');

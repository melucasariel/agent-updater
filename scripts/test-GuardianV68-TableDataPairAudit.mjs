#!/usr/bin/env node
import assert from 'node:assert/strict';
import {auditTocTableDataPairs} from './GuardianV68-TableDataPairAudit.mjs';
const fixture=[
 '1; 1 1 TABLE public account_private postgres',
 '2; 1 1 TABLE DATA public account_private postgres',
 '3; 1 1 TABLE internal private_without_data postgres',
 '4; 1 1 TABLE DATA public orphan_private postgres',
 '5; 1 1 TABLE "private schema" private_table postgres',
 '6; 1 1 TABLE DATA "private schema" private_table postgres',
 '7; 1 1 TABLE public duplicate_private postgres',
 '8; 1 1 TABLE public duplicate_private postgres',
 '9; 1 1 TABLE DATA public duplicate_private postgres',
 '10; 1 1 EXTENSION - pgcrypto'
].join('\n');
const r=auditTocTableDataPairs(fixture);
assert.equal(r.entries,10);
assert.equal(r.tableEntries,5);
assert.equal(r.dataEntries,4);
assert.equal(r.structurallyPaired,1);
assert.equal(r.unpairedSimpleTableEntries,3);
assert.equal(r.unpairedSimpleDataEntries,2);
assert.equal(r.ambiguousTableEntries,1);
assert.equal(r.ambiguousDataEntries,1);
assert.equal(r.duplicateOrNonUniqueEntries,3);
assert.equal(r.tableEntries,r.structurallyPaired+r.unpairedSimpleTableEntries+r.ambiguousTableEntries);
assert.equal(r.dataEntries,r.structurallyPaired+r.unpairedSimpleDataEntries+r.ambiguousDataEntries);
assert.equal(r.rowCountsVerified,false);
assert.equal(r.allTableDataVerified,false);
assert.equal(r.productionTouched,false);
for(const privateWord of ['account_private','private_without_data','orphan_private','private schema','duplicate_private','private_table'])
 assert.equal(JSON.stringify(r).includes(privateWord),false);
assert.throws(()=>auditTocTableDataPairs(fixture.replace('10; 1 1','9; 1 1')),e=>e.message==='TOC_DUPLICATE_ID');

// Regression: a repeated TABLE DATA identifier without a TABLE was previously
// omitted from the duplicate count. It must remain unmatched, not be paired.
const dataOnlyDup=[
 '1; 1 1 TABLE public one postgres',
 '2; 1 1 TABLE DATA public one postgres',
 '3; 1 1 TABLE DATA internal orphan_private postgres',
 '4; 1 1 TABLE DATA internal orphan_private postgres',
 '5; 1 1 EXTENSION - pgcrypto'
].join('\n');
const q=auditTocTableDataPairs(dataOnlyDup);
assert.equal(q.entries,5);
assert.equal(q.structurallyPaired,1);
assert.equal(q.unpairedSimpleTableEntries,0);
assert.equal(q.unpairedSimpleDataEntries,2);
assert.equal(q.duplicateOrNonUniqueEntries,2);
assert.equal(JSON.stringify(q).includes('orphan_private'),false);
// Repetition of the pair's DATA destroys its uniqueness.
const repeatedPair=auditTocTableDataPairs(dataOnlyDup.replace(
 '3; 1 1 TABLE DATA internal orphan_private postgres',
 '3; 1 1 TABLE DATA public one postgres'));
assert.equal(repeatedPair.structurallyPaired,0);
assert.equal(repeatedPair.unpairedSimpleTableEntries,1);
assert.equal(repeatedPair.unpairedSimpleDataEntries,3);
assert.equal(repeatedPair.duplicateOrNonUniqueEntries,3);
// Quoted/Unicode names and owners with spaces cannot be safely paired by
// the intentionally restrictive public TOC token grammar.
const uncertain=[
 '1; 1 1 TABLE public "mixed case" postgres',
 '2; 1 1 TABLE DATA public "mixed case" postgres',
 '3; 1 1 TABLE "quoted schema" fixture postgres',
 '4; 1 1 TABLE DATA "quoted schema" fixture postgres',
 '5; 1 1 TABLE public simple_fixture postgres',
 '6; 1 1 TABLE DATA public simple_fixture "complex owner"',
 '7; 1 1 TABLE public proprietário postgres',
 '8; 1 1 TABLE DATA public proprietário postgres',
 '9; 1 1 EXTENSION - pgcrypto'
].join('\n');
const u=auditTocTableDataPairs(uncertain);
assert.equal(u.structurallyPaired,0);
assert.equal(u.ambiguousTableEntries,3);
assert.equal(u.ambiguousDataEntries,4);
assert.equal(u.unpairedSimpleTableEntries,1);
assert.equal(u.unpairedSimpleDataEntries,0);
assert.equal(u.duplicateOrNonUniqueEntries,0);
for(const word of ['mixed case','quoted schema','proprietário','simple_fixture'])
 assert.equal(JSON.stringify(u).includes(word),false);
console.log('V68_DATA_ONLY_DUPLICATES_COUNTED=PASS');
console.log('V68_REPEATED_PAIR_DEMOTED=PASS');
console.log('V68_QUOTED_UNICODE_AND_OWNER_AMBIGUITY=PASS');

console.log('V68_TABLE_DATA_PAIR_COUNTS_RECONCILE=PASS');
console.log('V68_DUPLICATE_AND_AMBIGUOUS_FAIL_CLOSED=PASS');
console.log('V68_NO_PRIVATE_NAMES_OR_DATA_PROOF=PASS');

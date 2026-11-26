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
console.log('V68_TABLE_DATA_PAIR_COUNTS_RECONCILE=PASS');
console.log('V68_DUPLICATE_AND_AMBIGUOUS_FAIL_CLOSED=PASS');
console.log('V68_NO_PRIVATE_NAMES_OR_DATA_PROOF=PASS');

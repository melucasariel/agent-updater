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
// A difference between textual owner fields must not create a false pair.
// These strings are not authenticated global-role or ownership evidence.
const conflictingOwner=[
 '1; 1 1 TABLE public owned_private fixture_owner',
 '2; 1 1 TABLE DATA public owned_private other_owner',
 '3; 1 1 TABLE public valid_private fixture_owner',
 '4; 1 1 TABLE DATA public valid_private fixture_owner',
 '5; 1 1 EXTENSION - pgcrypto'
].join('\n');
const owners=auditTocTableDataPairs(conflictingOwner);
assert.equal(owners.structurallyPaired,1);
assert.equal(owners.unpairedSimpleTableEntries,1);
assert.equal(owners.unpairedSimpleDataEntries,1);
assert.equal(owners.duplicateOrNonUniqueEntries,0);
for(const word of ['owned_private','fixture_owner','other_owner'])
 assert.equal(JSON.stringify(owners).includes(word),false);
console.log('V68_OWNER_TOKEN_MISMATCH_NOT_PAIRED=PASS');

// Deterministic property tests: compare the auditor against independently
// computed cardinalities for mixed TABLE-only, DATA-only, unique and duplicate
// groups, in variable TOC order. No private backup content is read.
for(let seed=0;seed<64;seed++){
 const rows=[];
 let id=1,expectedPairs=0,expectedTables=0,expectedData=0;
 let expectedTableUnpaired=0,expectedDataUnpaired=0,expectedDuplicates=0;
 for(let i=0;i<5;i++)rows.push((id++)+'; 1 1 COMMENT - synthetic_metadata_owner_fixture');
 for(let k=0;k<9;k++){
  const t=(seed+k*3)%4,d=(seed*3+k)%4;
  const owner=(k%2===0)?'fixture_owner':'other_fixture_owner';
  const schema=(k%2===0)?'public':'synthetic';
  const name='fixture_key_'+k;
  const tt='TABLE '+schema+' '+name+' '+owner;
  const dd='TABLE DATA '+schema+' '+name+' '+owner;
  for(let j=0;j<t;j++)rows.push((id++)+'; 1 1 '+tt);
  for(let j=0;j<d;j++)rows.push((id++)+'; 1 1 '+dd);
  expectedTables+=t;expectedData+=d;
  if(t===1&&d===1)expectedPairs++;
  else{
   expectedTableUnpaired+=t;expectedDataUnpaired+=d;
   if(t>1||d>1)expectedDuplicates+=t+d;
  }
 }
 // Reverse order to ensure order-independent counters.
 if(seed%2===1)rows.reverse();
 const p=auditTocTableDataPairs(rows.join('\n'));
 assert.equal(p.tableEntries,expectedTables);
 assert.equal(p.dataEntries,expectedData);
 assert.equal(p.structurallyPaired,expectedPairs);
 assert.equal(p.unpairedSimpleTableEntries,expectedTableUnpaired);
 assert.equal(p.unpairedSimpleDataEntries,expectedDataUnpaired);
 assert.equal(p.duplicateOrNonUniqueEntries,expectedDuplicates);
 assert.equal(p.ambiguousDataEntries,0);
 assert.equal(p.ambiguousTableEntries,0);
 assert.equal(p.rowsVerified,undefined);
 assert.equal(p.rowCountsVerified,false);
}
console.log('V68_64_DETERMINISTIC_TOC_PROPERTY_CASES=PASS');

console.log('V68_DATA_ONLY_DUPLICATES_COUNTED=PASS');
console.log('V68_REPEATED_PAIR_DEMOTED=PASS');
console.log('V68_QUOTED_UNICODE_AND_OWNER_AMBIGUITY=PASS');

console.log('V68_TABLE_DATA_PAIR_COUNTS_RECONCILE=PASS');
console.log('V68_DUPLICATE_AND_AMBIGUOUS_FAIL_CLOSED=PASS');
console.log('V68_NO_PRIVATE_NAMES_OR_DATA_PROOF=PASS');

import assert from 'node:assert/strict';
import {auditTableScope} from './GuardianV67-TableScopeAudit.mjs';
const input=[
 '1; 1 1 TABLE public user_private_table private_owner',
 '2; 1 1 TABLE internal private_system_table hidden_owner',
 '3; 1 1 TABLE - no_schema_obj owner',
 '4; 1 1 TABLE "complex schema" private_table owner',
 '5; 1 1 TABLE DATA public user_private_table postgres',
 '6; 1 1 EXTENSION - pgcrypto'
].join('\n');
const a=auditTableScope(input);
assert.equal(a.catalogItems,6);
assert.equal(a.tableEntries,4);
assert.equal(a.tableDataEntries,1);
assert.equal(a.publicSchemaTableEntries,1);
assert.equal(a.otherSimpleSchemaTableEntries,1);
assert.equal(a.noSchemaTableEntries,1);
assert.equal(a.complexOrAmbiguousSchemaTableEntries,1);
assert.equal(a.publicSchemaTableEntries+a.otherSimpleSchemaTableEntries+
 a.noSchemaTableEntries+a.complexOrAmbiguousSchemaTableEntries,a.tableEntries);
assert.equal(a.originalUserTablesValidated,false);
assert.equal(a.tableDataRowsValidated,false);
assert.equal(a.historicalRolesVerified,false);
assert.equal(a.sqlExecuted,false);
assert.equal(a.productionTouched,false);
const serialized=JSON.stringify(a);
for(const secret of ['user_private_table','private_owner','private_system_table','hidden_owner','complex schema'])assert.equal(serialized.includes(secret),false);
assert.throws(()=>auditTableScope(input.replace('6; 1 1','1; 1 1')),e=>e.message==='TOC_DUPLICATE_ID');
console.log('V67_TABLE_SCOPE_PUBLIC_OTHER_COMPLEX_REDACTED=PASS');
console.log('V67_TABLE_ENTRIES_NOT_LIVE_TABLE_COUNT=PASS');
console.log('V67_NO_PRIVATE_IDENTIFIERS_OR_SQL=PASS');

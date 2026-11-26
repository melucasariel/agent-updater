import assert from 'node:assert/strict';
import {inspectToc} from './GuardianV64-TocDependencyPreflight.mjs';
const toc=[
 '; Archive created at synthetic fixture date',
 '; Contents of TOC:',
 '1; 2615 200 SCHEMA - public postgres',
 '2; 0 0 EXTENSION - pgcrypto postgres',
 '3; 0 0 EXTENSION - pg_net supabase_admin',
 '4; 1259 100 TABLE public rides postgres',
 '5; 0 100 TABLE DATA public rides postgres',
 '6; 1259 101 INDEX public rides_idx postgres',
 '7; 0 102 POLICY public select_policy supabase_admin',
 '8; 0 103 ACL public TABLE rides postgres',
 '9; 0 104 DEFAULT ACL public DEFAULT PRIVILEGES FOR TABLES postgres',
 '10; 0 0 COMMENT - EXTENSION pgcrypto postgres'
].join('\n')+'\n';
const meta={
 evidence:'CURRENT_METADATA_NOT_ORIGINAL_BACKUP_PROOF',
 roles:[{role:'postgres'}, {role:'anon'}],
 extensions:[{extension:'pgcrypto'}]
};
const r=inspectToc(toc,meta);
assert.equal(r.entries,10);
assert.equal(r.extensionsListed,2);
assert.equal(r.distinctExtensions,2);
assert.equal(r.distinctVisibleOwnerRoles,2);
assert.equal(r.missingOwnerRoles,1);
assert.equal(r.missingExtensionNames,1);
assert.equal(r.comparedToCurrent,true);
assert.equal(r.ambiguousOwner,0);
assert.equal(inspectToc(toc).comparedToCurrent,false);
assert.throws(()=>inspectToc(toc.replace('9; 0 104','8; 0 104')),e=>e.message==='TOC_DUPLICATE_ID');
assert.throws(()=>inspectToc(toc,{...meta,evidence:'HISTORICALLY_CONFIRMED'}),
 e=>e.message==='CURRENT_METADATA_INVALID');
assert.throws(()=>inspectToc('1; 0 1 TABLE x t p'),e=>e.message==='TOC_ITEMS_INVALID');
// The real PG17 pg_restore --list uses ownerless EXTENSION records.
// The extension name MUST NOT be included as an owner role candidate.
const ownerless=toc
 .replace('EXTENSION - pgcrypto postgres','EXTENSION - pgcrypto')
 .replace('EXTENSION - pg_net supabase_admin','EXTENSION - pg_net');
const ownerlessInfo=inspectToc(ownerless,meta);
assert.equal(ownerlessInfo.extensionsListed,2);
assert.equal(ownerlessInfo.distinctExtensions,2);
assert.equal(ownerlessInfo.distinctVisibleOwnerRoles,2);
assert.equal(ownerlessInfo.missingExtensionNames,1);
assert.equal(ownerlessInfo.ambiguousOwner,0);
const extensionOnly=ownerless.replaceAll('postgres','-').replaceAll('supabase_admin','-');
assert.equal(inspectToc(extensionOnly).distinctExtensions,2);
assert.equal(inspectToc(extensionOnly).distinctVisibleOwnerRoles,0);
const flipped=toc.replace('EXTENSION - pg_net supabase_admin','EXTENSION - pg_trgm supabase_admin');
assert.notEqual(inspectToc(toc).dependencyFingerprint16,inspectToc(flipped).dependencyFingerprint16);
console.log('V64_ARCHIVE_OWNER_EXTENSION_COUNTS=PASS');
console.log('V64_OWNERLESS_PG17_EXTENSION_NAMES_NOT_ROLES=PASS');
console.log('V64_CURRENT_ROSTER_DIFFERENCE_NOT_HISTORICAL_PROOF=PASS');
console.log('V64_TOC_DUPLICATES_INVALID_SOURCE=BLOCKED');
console.log('V64_NO_SQL_NO_DB_NO_PRIVATE_NAMES_PRINTED=YES');

#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {inspectCurrentMetadata} from './GuardianV62-CurrentDependencyEvidence.mjs';
const base={
 evidence:'CURRENT_METADATA_NOT_ORIGINAL_BACKUP_PROOF',
 postgres_version:'17.12',
 roles:[
  {role:'anon',login:false,superuser:false,bypass_rls:false},
  {role:'authenticated',login:false,superuser:false,bypass_rls:false},
  {role:'postgres',login:true,superuser:false,bypass_rls:true},
  {role:'supabase_admin',login:true,superuser:true,bypass_rls:true}
 ],
 extensions:[
  {extension:'pg_cron',version:'1.6.4',schema:'pg_catalog'},
  {extension:'pg_net',version:'0.20.4',schema:'public'},
  {extension:'pgcrypto',version:'1.3',schema:'extensions'},
  {extension:'plpgsql',version:'1.0',schema:'pg_catalog'}
 ],
 object_owners:['postgres','supabase_admin'],
 default_acl_entries:27
};
const valid=inspectCurrentMetadata(base);
assert.equal(valid.roles,4);assert.equal(valid.extensions,4);
assert.equal(valid.networkOrJobExtensions,2);
assert.equal(valid.superusers,1);assert.equal(valid.bypassRoles,2);
assert.equal(valid.owners,2);assert.equal(valid.defaultAcl,27);
function rejects(d,msg){assert.throws(()=>inspectCurrentMetadata(d),e=>e.message===msg);}
rejects({...base,evidence:'ORIGINAL_BACKUP_PROOF'},'INVALID_METADATA');
rejects({...base,roles:[...base.roles,base.roles[0]]},'INVALID_ROLE_METADATA');
rejects({...base,object_owners:['unknown']},'UNKNOWN_OWNER_ROLE');
rejects({...base,extensions:[...base.extensions,base.extensions[0]]},'INVALID_EXTENSION_METADATA');
rejects({...base,credentials:'PRIVATE_TOKEN'},'UNEXPECTED_FIELDS');
console.log('V62_CURRENT_VS_ORIGINAL_BACKUP_PROVENANCE=SEPARATED');
console.log('V62_ROLES_EXTENSIONS_RLS_PRIVILEGE_COUNTS=PASS');
console.log('V62_UNKNOWN_OWNER_DUPLICATES_SECRETS=BLOCKED');
console.log('V62_SQL_EXECUTED=NO');

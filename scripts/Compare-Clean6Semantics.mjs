#!/usr/bin/env node
// ROTA62 CLEAN6 - OFFLINE semantic manifest comparer. Never touches PostgreSQL or Docker.
// JSON schema: {format:"r62-clean6-semantic-v1", owners:[{id,owner}], acls:[{id,grantee,privilege,grantor,grantable}]}
import fs from 'node:fs';
import crypto from 'node:crypto';

function fail(code) { process.stdout.write('STATUS=BLOCKED\nCODE='+code+'\nSQL_EXECUTED=NO\n'); process.exitCode=2; }
const args=process.argv.slice(2);
function arg(flag){const pos=args.indexOf(flag);return pos>=0?args[pos+1]:undefined;}
const ex=arg('--expected'), ac=arg('--actual');
const normal=(v)=>typeof v==='string' && v.length>0 && v.length<=1024;
const sort=(a,b)=>a.localeCompare(b);
const key=(v)=>JSON.stringify(v);
function read(path) {
  const st=fs.statSync(path);
  if(!st.isFile()||st.size>5242880)throw Error('INVALID_FILE');
  const data=JSON.parse(fs.readFileSync(path,'utf8'));
  if(!data||data.format!=='r62-clean6-semantic-v1'||!Array.isArray(data.owners)||!Array.isArray(data.acls))throw Error('INVALID_SCHEMA');
  if(data.owners.length>10000||data.acls.length>100000)throw Error('EXCESSIVE_ROWS');
  const owners=new Map(),acls=new Set();
  for(const x of data.owners) {
    if(!x||!normal(x.id)||!normal(x.owner)||owners.has(x.id))throw Error('INVALID_OWNER_RECORD');
    owners.set(x.id,x.owner);
  }
  for(const x of data.acls){
    if(!x||!normal(x.id)||!normal(x.grantee)||!normal(x.privilege)||!normal(x.grantor)||typeof x.grantable!=='boolean')throw Error('INVALID_ACL_RECORD');
    const k=key([x.id,x.grantee,x.privilege,x.grantor,x.grantable]);
    if(acls.has(k))throw Error('DUPLICATE_ACL_RECORD');acls.add(k);
  }
  return {owners,acls};
}
try {
  if(args.length!==4||!ex||!ac||ex===ac)throw Error('INVALID_ARGUMENTS');
  const expected=read(ex),actual=read(ac);
  const eo=expected.owners.size,ea=expected.acls.size;
  const missingOwners=[...expected.owners.keys()].filter(id=>!actual.owners.has(id));
  const changedOwners=[...expected.owners.keys()].filter(id=>actual.owners.has(id)&&actual.owners.get(id)!==expected.owners.get(id));
  const extraOwners=[...actual.owners.keys()].filter(id=>!expected.owners.has(id));
  const missingAcls=[...expected.acls].filter(a=>!actual.acls.has(a));
  const extraAcls=[...actual.acls].filter(a=>!expected.acls.has(a));
  const exact=missingOwners.length===0&&changedOwners.length===0&&extraOwners.length===0&&missingAcls.length===0&&extraAcls.length===0;
  process.stdout.write('=== ROTA62 CLEAN6 OFFLINE SEMANTIC COMPARISON ===\n');
  process.stdout.write('MODE=OFFLINE_MANIFESTS_NO_DB_NO_PASSWORD\n');
  const fields={
    EXPECTED_OWNER_RECORDS:eo,EXPECTED_ACL_RECORDS:ea,ACTUAL_OWNER_RECORDS:actual.owners.size,ACTUAL_ACL_RECORDS:actual.acls.size,
    MISSING_OWNERS:missingOwners.length,CHANGED_OWNERS:changedOwners.length,EXTRA_OWNERS:extraOwners.length,
    MISSING_ACLS:missingAcls.length,EXTRA_ACLS:extraAcls.length,
    EXPECTED_TARGET_185_595:(eo===185&&ea===595)?'YES':'NO',
    CONTENT_MATCH:exact?'YES':'NO',SQL_EXECUTED:'NO',ROLLBACK_EXECUTED:'NO',DATABASE_NOT_ACCESSED:'YES',
    REAL_CLEAN6_VERIFIED:'NO'
  };
  for(const [k,v] of Object.entries(fields))process.stdout.write(k+'='+v+'\n');
  // Numeric counts alone cannot establish provenance of manifests.
  process.stdout.write('RESULT='+((exact&&eo===185&&ea===595)?'OFFLINE_MANIFESTS_MATCH_UNVERIFIED_PROVENANCE':'NOT_VERIFIED')+'\nEND_REPORT_OK\n');
  if(!exact||eo!==185||ea!==595)process.exitCode=1;
} catch (e) {
  const allowed=new Set(['INVALID_FILE','INVALID_SCHEMA','EXCESSIVE_ROWS','INVALID_OWNER_RECORD','INVALID_ACL_RECORD','DUPLICATE_ACL_RECORD','INVALID_ARGUMENTS']);
  fail(allowed.has(e.message)?e.message:'INPUT_ERROR_REDACTED');
}

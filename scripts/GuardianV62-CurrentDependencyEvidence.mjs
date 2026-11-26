#!/usr/bin/env node
/**
 * Guardian V6.2: CURRENT Supabase PG17 metadata readiness triage.
 * Reads only the JSON object from the read-only SQL dependency query.
 * It NEVER executes SQL or provisions privileged/managed roles.
 * A current metadata snapshot cannot attest the state of an older backup.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const fail=k=>{throw Error(k);};
const REQUIRED=['roles','extensions','object_owners','postgres_version','default_acl_entries','evidence'];
const ALLOWED_ROLE_FIELDS=['role','login','superuser','bypass_rls'];
const ALLOWED_EXT_FIELDS=['schema','version','extension'];
const EXPECTED='CURRENT_METADATA_NOT_ORIGINAL_BACKUP_PROOF';
const HIGH_RISK_EXTS=new Set(['pg_cron','pg_net','http','dblink','postgres_fdw']);
function exact(obj,keys){
 if(!obj||typeof obj!=='object'||Array.isArray(obj)||
  Object.keys(obj).sort().join('|')!==keys.slice().sort().join('|'))fail('UNEXPECTED_FIELDS');
}
function safeId(s){return typeof s==='string'&&/^[a-zA-Z_][a-zA-Z0-9_$-]{0,100}$/.test(s);}
export function inspectCurrentMetadata(data){
 exact(data,REQUIRED);
 if(data.evidence!==EXPECTED||typeof data.postgres_version!=='string'||
  !/^17\.[0-9]{1,3}(?:\.[0-9]{1,3})?$/.test(data.postgres_version)||
  !Number.isInteger(data.default_acl_entries)||data.default_acl_entries<0||data.default_acl_entries>100000||
  !Array.isArray(data.roles)||data.roles.length<1||data.roles.length>300||
  !Array.isArray(data.extensions)||data.extensions.length<1||data.extensions.length>100||
  !Array.isArray(data.object_owners)||data.object_owners.length<1||data.object_owners.length>100)fail('INVALID_METADATA');
 const roleSet=new Set(),extSet=new Set(),ownerSet=new Set();
 let superusers=0,bypassRoles=0,loginRoles=0;
 for(const role of data.roles){
  exact(role,ALLOWED_ROLE_FIELDS);
  if(!safeId(role.role)||roleSet.has(role.role)||typeof role.login!=='boolean'||
   typeof role.superuser!=='boolean'||typeof role.bypass_rls!=='boolean')fail('INVALID_ROLE_METADATA');
  roleSet.add(role.role);
  superusers+=Number(role.superuser);bypassRoles+=Number(role.bypass_rls);
  loginRoles+=Number(role.login);
 }
 const riskExts=[];
 for(const ext of data.extensions){
  exact(ext,ALLOWED_EXT_FIELDS);
  if(!safeId(ext.extension)||!safeId(ext.schema)||typeof ext.version!=='string'||
   !/^[0-9a-zA-Z_.-]{1,40}$/.test(ext.version)||extSet.has(ext.extension))fail('INVALID_EXTENSION_METADATA');
  extSet.add(ext.extension);
  if(HIGH_RISK_EXTS.has(ext.extension))riskExts.push(ext.extension);
 }
 for(const owner of data.object_owners){
  if(!safeId(owner)||ownerSet.has(owner)||!roleSet.has(owner))fail('UNKNOWN_OWNER_ROLE');
  ownerSet.add(owner);
 }
 const state=crypto.createHash('sha256').update(JSON.stringify({
  roles:[...data.roles].sort((a,b)=>a.role.localeCompare(b.role)),
  extensions:[...data.extensions].sort((a,b)=>a.extension.localeCompare(b.extension)),
  owners:[...ownerSet].sort(),version:data.postgres_version,defaultAclEntries:data.default_acl_entries
 })).digest('hex').slice(0,16).toUpperCase();
 return {roles:roleSet.size,extensions:extSet.size,owners:ownerSet.size,
  superusers,bypassRoles,loginRoles,defaultAcl:data.default_acl_entries,
  networkOrJobExtensions:riskExts.length,fingerprint16:state,
  extensionNames:new Set(extSet)};
}
function cli(args){
 if(args.length!==2||args[0]!=='--current-metadata'||!path.isAbsolute(args[1]))fail('USAGE');
 const st=fs.lstatSync(args[1]);
 if(!st.isFile()||st.isSymbolicLink()||st.size>1024*1024||st.size<20)fail('INPUT_INVALID');
 let data;try{data=JSON.parse(fs.readFileSync(args[1],'utf8'));}catch{fail('JSON_INVALID');}
 const r=inspectCurrentMetadata(data);
 const line=['=== ROTA62 GUARDIAN V6.2 CURRENT DEPENDENCIES ===',
  'CURRENT_METADATA_SCHEMA_VALIDATED=YES',
  'POSTGRES_MAJOR_17=YES',
  'CURRENT_ROLES='+r.roles,'CURRENT_LOGIN_ROLES='+r.loginRoles,
  'CURRENT_SUPERUSER_ROLES='+r.superusers,'CURRENT_BYPASSRLS_ROLES='+r.bypassRoles,
  'CURRENT_OBJECT_OWNER_ROLES='+r.owners,
  'CURRENT_EXTENSIONS='+r.extensions,
  'CURRENT_NETWORK_OR_JOB_EXTENSIONS='+r.networkOrJobExtensions,
  'CURRENT_DEFAULT_ACL_ENTRIES='+r.defaultAcl,
  'CURRENT_METADATA_FINGERPRINT_SHA16='+r.fingerprint16,
  'ORIGINAL_BACKUP_ROLES_ATTESTED=NO',
  'ORIGINAL_BACKUP_EXTENSIONS_ATTESTED=NO',
  'SIX_BACKUP_TOC_EXTENSIONS_EQUAL_SEVEN_INSTALLED_PROVEN=NO',
  'SUPABASE_MANAGED_ROLES_SAFE_TO_AUTO_CREATE=NO',
  'GLOBALS_EXECUTED=NO','SQL_EXECUTED=NO',
  'PRODUCTION_TOUCHED=NO','READY_TO_RESTORE_REAL_BACKUP=NO','END_REPORT_OK'];
 console.log(line.join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{cli(process.argv.slice(2));}
 catch(e){
  const known=new Set(['USAGE','INPUT_INVALID','JSON_INVALID','INVALID_METADATA','INVALID_ROLE_METADATA',
    'INVALID_EXTENSION_METADATA','UNKNOWN_OWNER_ROLE','UNEXPECTED_FIELDS']);
  console.log('=== ROTA62 GUARDIAN V6.2 CURRENT DEPENDENCIES ===\nSTATUS=BLOCKED_'+
   (known.has(e.message)?e.message:'REDACTED')+'\nSQL_EXECUTED=NO\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

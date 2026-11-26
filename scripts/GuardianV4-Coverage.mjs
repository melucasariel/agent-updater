#!/usr/bin/env node
// ROTA62 Guardian V4: offline completeness gate and integrity inventory.
// Never bundles plaintext, decrypts, uploads, calls APIs, or changes production.
// Local only. Config describes EXISTING snapshots, not how to capture them.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import crypto from 'node:crypto';
const names=['database','web','api','storage','dns','config','secrets-vault'];
const fileRoles=new Set(['database','dns','config','secrets-vault']);
function err(code){throw Error(code)}
function obj(x){return x&&typeof x==='object'&&!Array.isArray(x)}
export function parseConfig(src){
 const cfg=JSON.parse(src);
 if(!obj(cfg)||cfg.format!=='r62-guardian-v4-input-1'||!obj(cfg.components))err('INVALID_CONFIG');
 for(const k of Object.keys(cfg.components))if(!names.includes(k))err('UNKNOWN_COMPONENT');
 for(const k of names){
  const v=cfg.components[k];
  if(!obj(v)||typeof v.path!=='string'||!path.isAbsolute(v.path)||v.path.includes('\0'))err('INVALID_COMPONENT_PATH');
  if(k==='database'&&(!/^[a-f0-9]{64}$/i.test(v.sha256||'')))err('DATABASE_HASH_REQUIRED');
  if(fileRoles.has(k)&&v.kind!=='file')err('INVALID_KIND');
  if(!fileRoles.has(k)&&v.kind!=='directory')err('INVALID_KIND');
 }
 return cfg;
}
function safeWalk(root,kind){
 const top=fs.lstatSync(root);
 if(top.isSymbolicLink())err('SYMLINK_BLOCKED');
 if(kind==='file'){
  if(!top.isFile())err('EXPECTED_FILE');
  return [{full:root,rel:path.basename(root),bytes:top.size}];
 }
 if(!top.isDirectory())err('EXPECTED_DIRECTORY');
 const all=[],queue=[{dir:root,rel:''}];let count=0,bytes=0;
 while(queue.length){
  const {dir,rel}=queue.shift();
  const entries=fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name));
  for(const entry of entries){
   if(++count>10000)err('FILE_LIMIT');
   if(entry.isSymbolicLink())err('SYMLINK_BLOCKED');
   const full=path.join(dir,entry.name),relative=path.posix.join(rel,entry.name);
   if(entry.isDirectory())queue.push({dir:full,rel:relative});
   else if(entry.isFile()){
    const st=fs.lstatSync(full);bytes+=st.size;
    if(bytes>10*1024*1024*1024)err('BYTE_LIMIT');
    all.push({full,rel:relative,bytes:st.size});
   }else err('UNSUPPORTED_FILE_TYPE');
  }
 }
 if(!all.length)err('EMPTY_DIRECTORY');
 return all;
}
function shaFile(full){
 const hash=crypto.createHash('sha256');
 const fd=fs.openSync(full,'r');
 try{
  const buffer=Buffer.allocUnsafe(1024*1024);
  for(;;){const n=fs.readSync(fd,buffer,0,buffer.length,null);if(!n)break;hash.update(buffer.subarray(0,n));}
 }finally{fs.closeSync(fd);}
 return hash.digest('hex');
}
export function verify(cfg){
 const results=[],blocked=[];
 const paths=new Set();
 for(const k of names){
  const v=cfg.components[k];
  try{
   const root=fs.realpathSync(v.path);
   if(paths.has(root.toLowerCase()))err('DUPLICATED_COMPONENT_PATH');
   paths.add(root.toLowerCase());
   if(k==='database'&&!v.path.toLowerCase().endsWith('.r62db'))err('BAD_DATABASE_EXTENSION');
   const files=safeWalk(v.path,v.kind);
   const entries=files.map(f=>({rel:f.rel,bytes:f.bytes,sha256:shaFile(f.full)})).sort((a,b)=>a.rel.localeCompare(b.rel));
   if(k==='database'&&entries[0].sha256.toLowerCase()!==v.sha256.toLowerCase())err('DATABASE_HASH_MISMATCH');
   const aggregate=crypto.createHash('sha256').update(JSON.stringify(entries)).digest('hex');
   results.push({component:k,status:'VERIFIED_FILE_BYTES',files:entries.length,bytes:entries.reduce((a,f)=>a+f.bytes,0),fingerprint:aggregate.slice(0,16).toUpperCase()});
  }catch(e){
   const permitted=['DUPLICATED_COMPONENT_PATH','BAD_DATABASE_EXTENSION','DATABASE_HASH_MISMATCH','SYMLINK_BLOCKED','EXPECTED_FILE','EXPECTED_DIRECTORY','FILE_LIMIT','BYTE_LIMIT','UNSUPPORTED_FILE_TYPE','EMPTY_DIRECTORY'];
   blocked.push({component:k,status:permitted.includes(e.message)?e.message:'MISSING_OR_UNREADABLE'});
  }
 }
 return {results,blocked,complete:blocked.length===0};
}
function cli(argv){
 const args={};
 if(argv.length%2||argv.length===0)err('USAGE');
 for(let i=0;i<argv.length;i+=2){
  if(!['--config','--mode'].includes(argv[i])||args[argv[i]])err('USAGE');
  args[argv[i]]=argv[i+1];
 }
 if(!['plan','verify'].includes(args['--mode']))err('USAGE');
 const cfg=parseConfig(fs.readFileSync(args['--config'],'utf8'));
 if(args['--mode']==='plan'){
  console.log('=== ROTA62 GUARDIAN V4 COVERAGE PLAN ===');
  for(const k of names)console.log('COMPONENT_'+k.toUpperCase().replaceAll('-','_')+'=DECLARED');
  console.log('STATUS=CONFIG_SCHEMA_VALID');
  console.log('BACKUP_CAPTURED=NO');
  console.log('END_REPORT_OK');
  return;
 }
 const result=verify(cfg);
 console.log('=== ROTA62 GUARDIAN V4 COVERAGE VERIFY ===');
 for(const x of result.results){
  const name=x.component.toUpperCase().replaceAll('-','_');
  console.log('COMPONENT_'+name+'_STATUS='+x.status);
  console.log('COMPONENT_'+name+'_FILES='+x.files);
  console.log('COMPONENT_'+name+'_BYTES='+x.bytes);
  console.log('COMPONENT_'+name+'_FINGERPRINT16='+x.fingerprint);
 }
 for(const x of result.blocked)console.log('COMPONENT_'+x.component.toUpperCase().replaceAll('-','_')+'_STATUS=BLOCKED_'+x.status);
 console.log('COMPONENTS_VERIFIED='+result.results.length+'/7');
 console.log('FILE_COVERAGE_GATE='+(result.complete?'PASS':'BLOCKED'));
 console.log('BACKUP_CAPTURED_BY_THIS_TOOL=NO');
 console.log('CONFIGURATION_SEMANTICS_VERIFIED=NO');
 console.log('BACKUP_RECOVERY_VERIFIED=NO');
 console.log('NO_FILE_CONTENTS_UPLOADED=YES');
 console.log('END_REPORT_OK');
 if(!result.complete)process.exitCode=2;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{cli(process.argv.slice(2));}catch(e){
  console.log('=== ROTA62 GUARDIAN V4 ===');
  console.log('STATUS=BLOCKED_'+(['USAGE','INVALID_CONFIG','UNKNOWN_COMPONENT','INVALID_COMPONENT_PATH','DATABASE_HASH_REQUIRED','INVALID_KIND'].includes(e.message)?e.message:'REDACTED'));
  console.log('END_REPORT_OK');process.exitCode=2;
 }
}

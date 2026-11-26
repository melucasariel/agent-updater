#!/usr/bin/env node
// Guardian V6.0 — manual snapshot packager for ALREADY CAPTURED local files.
// Atomic new bundle only. Does not capture LIVE Web/API/Storage/DNS or copy vault.
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const ROLES=['database','web','api','storage','dns','config','globals','secrets-vault'];
const fail=x=>{throw Error(x);};
const HASH=/^[a-f0-9]{64}$/i, ID=/^[a-zA-Z0-9][a-zA-Z0-9._-]{7,99}$/;
const MARKER='.rota62-guardian-lab-only';
const MARKER_VALUE='ROTA62_OFFLINE_LAB_V1\n';
const MAX=10*1024**3;
function within(parent,child){
 const r=path.relative(parent,child);
 return r===''||(!r.startsWith('..'+path.sep)&&r!=='..'&&!path.isAbsolute(r));
}
function statFile(file){
 if(typeof file!=='string'||!path.isAbsolute(file))fail('PATH_MUST_BE_ABSOLUTE');
 const st=fs.lstatSync(file);
 if(!st.isFile()||st.isSymbolicLink()||st.size<64||st.size>MAX)fail('SOURCE_FILE_INVALID');
 if(fs.realpathSync(file)!==path.resolve(file))fail('SOURCE_ANCESTOR_SYMLINK');
 return st;
}
function digest(file){
 const fd=fs.openSync(file,'r'),h=crypto.createHash('sha256');
 try{
  const b=Buffer.allocUnsafe(1024*1024);
  while(true){const n=fs.readSync(fd,b,0,b.length,null);if(!n)break;h.update(b.subarray(0,n));}
 }finally{fs.closeSync(fd);}
 return h.digest('hex');
}
export function prepareOfflineBundle({configFile,labRoot}){
 if(typeof labRoot!=='string'||!path.isAbsolute(labRoot)||!path.isAbsolute(configFile))fail('PATH_MUST_BE_ABSOLUTE');
 const rootSt=fs.lstatSync(labRoot);
 if(!rootSt.isDirectory()||rootSt.isSymbolicLink()||fs.realpathSync(labRoot)!==path.resolve(labRoot)||
  path.resolve(labRoot)===path.parse(labRoot).root)fail('LAB_ROOT_UNSAFE');
 const marker=path.join(labRoot,MARKER);
 if(fs.lstatSync(marker).isSymbolicLink()||fs.readFileSync(marker,'utf8')!==MARKER_VALUE)fail('LAB_MARKER_INVALID');
 const configStat=statFile(configFile);
 if(configStat.size>65536)fail('CONFIG_TOO_BIG');
 let cfg;try{cfg=JSON.parse(fs.readFileSync(configFile,'utf8'));}catch{fail('INVALID_CONFIG');}
 if(!cfg||typeof cfg!=='object'||Array.isArray(cfg)||
  Object.keys(cfg).sort().join(',')!==['captureId','components','format','release'].sort().join(',')||
  cfg.format!=='r62-guardian-v60-prepared-files-1'||!ID.test(cfg.captureId)||!ID.test(cfg.release)||
  !cfg.components||typeof cfg.components!=='object'||Array.isArray(cfg.components)||
  Object.keys(cfg.components).sort().join(',')!==[...ROLES].sort().join(','))fail('INVALID_CONFIG');
 if(within(labRoot,configFile))fail('SOURCE_OVERLAPS_LAB');
 const data=[],seen=new Set();
 for(const role of ROLES){
  const v=cfg.components[role];
  if(!v||typeof v!=='object'||Array.isArray(v)||
   Object.keys(v).sort().join(',')!=='path,sha256'||!HASH.test(v.sha256||''))fail('INVALID_COMPONENT');
  const st=statFile(v.path),real=fs.realpathSync(v.path);
  if(within(labRoot,real)||within(real,labRoot)||seen.has(real))fail('SOURCE_OVERLAPS_LAB');
  seen.add(real);
  if(role==='database'){
   const fd=fs.openSync(v.path,'r');const b=Buffer.alloc(8);
   try{if(fs.readSync(fd,b,0,8,0)!==8||b.toString('ascii')!=='R62DB02\n')fail('DATABASE_MAGIC_INVALID');}
   finally{fs.closeSync(fd);}
  }
  data.push({role,source:v.path,bytes:st.size,sha256:v.sha256.toLowerCase()});
 }
 const dest=path.join(labRoot,'backup-'+cfg.captureId);
 if(fs.existsSync(dest))fail('BUNDLE_ALREADY_EXISTS');
 // Do not write even temp files unless ALL expected source hashes match.
 for(const x of data)if(digest(x.source)!==x.sha256)fail('SOURCE_HASH_MISMATCH');
 const tmp=fs.mkdtempSync(path.join(labRoot,'.r62-v60-building-'));
 let done=false;
 try{
  for(const x of data){
   if(x.role==='secrets-vault')continue; // NEVER copy vault into the bundle.
   const to=path.join(tmp,x.role,'snapshot.bin');
   fs.mkdirSync(path.dirname(to),{recursive:true,mode:0o700});
   fs.copyFileSync(x.source,to,fs.constants.COPYFILE_EXCL);
   try{fs.chmodSync(to,0o600)}catch{}
   if(fs.statSync(to).size!==x.bytes||digest(to)!==x.sha256||
      digest(x.source)!==x.sha256)fail('FILE_CHANGED_DURING_COPY');
  }
  const vault=data.find(x=>x.role==='secrets-vault');
  if(digest(vault.source)!==vault.sha256)fail('VAULT_CHANGED');
  if(fs.existsSync(dest))fail('BUNDLE_ALREADY_EXISTS');
  fs.renameSync(tmp,dest);
  done=true;
  return {componentsCopied:7,externalVaultPreserved:true,captureId:cfg.captureId};
 }finally{if(!done)fs.rmSync(tmp,{force:true,recursive:true});}
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const a=process.argv.slice(2);
  if(a.length!==4||a[0]!=='--prepared-config'||a[2]!=='--offline-lab')fail('USAGE');
  const result=prepareOfflineBundle({configFile:a[1],labRoot:a[3]});
  console.log(['=== ROTA62 GUARDIAN V6.0 MANUAL BACKUP PREPARE ===',
   'OFFLINE_BUNDLE_CREATED=YES','COPIED_COMPONENTS='+result.componentsCopied,
   'EXTERNAL_VAULT_NOT_COPIED=YES','ATOMIC_NEW_BUNDLE=YES',
   'BUNDLE_SIGNED=NO','LIVE_SERVICES_CAPTURED_BY_THIS_TOOL=NO',
   'DATABASE_RESTORED=NO','PRODUCTION_TOUCHED=NO',
   'RECOVERY_READY=NO','END_REPORT_OK'].join('\n'));
 }catch(e){
  const known=new Set(['USAGE','PATH_MUST_BE_ABSOLUTE','SOURCE_FILE_INVALID',
   'SOURCE_ANCESTOR_SYMLINK','LAB_ROOT_UNSAFE','LAB_MARKER_INVALID',
   'CONFIG_TOO_BIG','INVALID_CONFIG','INVALID_COMPONENT','SOURCE_OVERLAPS_LAB',
   'DATABASE_MAGIC_INVALID','BUNDLE_ALREADY_EXISTS','SOURCE_HASH_MISMATCH',
   'FILE_CHANGED_DURING_COPY','VAULT_CHANGED']);
  console.log('=== ROTA62 GUARDIAN V6.0 MANUAL BACKUP PREPARE ===\nSTATUS=BLOCKED_'+
   (known.has(e.message)?e.message:'REDACTED')+
   '\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

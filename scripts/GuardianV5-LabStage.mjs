#!/usr/bin/env node
// Guardian V5 — offline, fail-closed, atomic local recovery staging.
// Never executes a restore, SQL, deployment, network request, or decryption.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {parseConfig,verify} from './GuardianV4-Coverage.mjs';

const ROLES=['database','web','api','storage','dns','config'];
const FILE_ROLES=new Set(['database','dns','config']);
const MARKER='.rota62-guardian-lab-only';
const MARKER_CONTENT='ROTA62_OFFLINE_LAB_V1\n';
const MAX_FILES=10000, MAX_BYTES=10*1024**3;
const fail=s=>{throw Error(s);};
const hashFile=f=>{
 const h=crypto.createHash('sha256'),fd=fs.openSync(f,'r');
 try{
  const buf=Buffer.allocUnsafe(1024*1024);
  for(;;){const n=fs.readSync(fd,buf,0,buf.length,null);if(!n)break;h.update(buf.subarray(0,n));}
 }finally{fs.closeSync(fd);}
 return h.digest('hex');
};
function within(parent,child){
 const rel=path.relative(parent,child);
 return rel===''||(!rel.startsWith('..'+path.sep)&&rel!=='..'&&!path.isAbsolute(rel));
}
function validateLabRoot(lab,cfg){
 if(!path.isAbsolute(lab))fail('LAB_PATH_NOT_ABSOLUTE');
 const root=path.parse(lab).root;
 if(path.resolve(lab)===root)fail('LAB_CANNOT_BE_DISK_ROOT');
 // Do not allow symlinks at the lab root or in the marker.
 if(fs.lstatSync(lab).isSymbolicLink()||!fs.lstatSync(lab).isDirectory())fail('LAB_INVALID');
 if(fs.realpathSync(lab)!==path.resolve(lab))fail('LAB_SYMLINK_ANCESTOR');
 const marker=path.join(lab,MARKER);
 if(fs.lstatSync(marker).isSymbolicLink()||!fs.lstatSync(marker).isFile())fail('LAB_MARKER_INVALID');
 if(fs.readFileSync(marker,'utf8')!==MARKER_CONTENT)fail('LAB_MARKER_INVALID');
 for(const [role,v] of Object.entries(cfg.components)){
  const source=fs.realpathSync(v.path);
  if(within(source,lab)||within(lab,source))fail('LAB_OVERLAPS_SOURCE');
 }
}
function listFiles(root,kind){
 const top=fs.lstatSync(root);
 if(top.isSymbolicLink())fail('SYMLINK_BLOCKED');
 if(kind==='file'){
  if(!top.isFile())fail('WRONG_COMPONENT_KIND');
  return [{src:root,rel:root.endsWith('.r62db')?'snapshot.r62db':'snapshot',bytes:top.size}];
 }
 if(!top.isDirectory())fail('WRONG_COMPONENT_KIND');
 const files=[], queue=[{src:root,rel:''}];let scanned=0,total=0;
 while(queue.length){
  const cur=queue.shift();
  for(const e of fs.readdirSync(cur.src,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name))){
   if(++scanned>MAX_FILES)fail('FILE_LIMIT');
   const full=path.join(cur.src,e.name),rel=path.posix.join(cur.rel,e.name);
   const info=fs.lstatSync(full);
   if(info.isSymbolicLink())fail('SYMLINK_BLOCKED');
   if(info.isDirectory())queue.push({src:full,rel});
   else if(info.isFile()){
    total+=info.size;
    if(total>MAX_BYTES)fail('BYTE_LIMIT');
    files.push({src:full,rel,bytes:info.size});
   }else fail('SPECIAL_FILE_BLOCKED');
  }
 }
 if(!files.length)fail('EMPTY_COMPONENT');
 return files;
}
export function inventory(cfg){
 const gate=verify(cfg);
 if(!gate.complete)fail('SEVEN_COMPONENTS_NOT_VERIFIED');
 const entries=[],seen=new Set();
 for(const role of ROLES){
  const v=cfg.components[role];
  const files=listFiles(v.path,v.kind);
  for(const f of files){
   const name=role+'/'+f.rel;
   if(seen.has(name))fail('DUPLICATE_PATH');
   seen.add(name);
   const sha256=hashFile(f.src);
   if(role==='database'&&sha256.toLowerCase()!==v.sha256.toLowerCase())fail('DB_HASH_MISMATCH');
   entries.push({role,name,source:f.src,bytes:f.bytes,sha256});
  }
 }
 entries.sort((a,b)=>a.name.localeCompare(b.name));
 return entries;
}
function safeCopy(from,to,want){
 if(fs.lstatSync(from).isSymbolicLink())fail('SOURCE_SYMLINK');
 fs.mkdirSync(path.dirname(to),{recursive:true,mode:0o700});
 fs.copyFileSync(from,to,fs.constants.COPYFILE_EXCL);
 try{fs.chmodSync(to,0o600);}catch{}
 if(hashFile(to)!==want)fail('STAGED_HASH_MISMATCH');
 if(hashFile(from)!==want)fail('SOURCE_CHANGED_DURING_COPY');
}
export function prepare({cfg,lab,mode}){
 if(!['plan','stage'].includes(mode))fail('INVALID_MODE');
 validateLabRoot(lab,cfg);
 const entries=inventory(cfg);
 const db=entries.find(x=>x.role==='database');
 const stageName='restore-'+db.sha256.slice(0,16).toLowerCase();
 const target=path.join(lab,stageName);
 if(fs.existsSync(target))fail('TARGET_EXISTS_NO_OVERWRITE');
 const total=entries.reduce((sum,x)=>sum+x.bytes,0);
 if(mode==='plan')return {mode,files:entries.length,total,targetCreated:false,componentRoles:6};
 const tmp=fs.mkdtempSync(path.join(lab,'.r62-staging-'));
 let published=false;
 try{
  for(const e of entries)safeCopy(e.source,path.join(tmp,e.name),e.sha256);
  // Only paths RELATIVE to this local staging folder; never persist original private paths.
  const manifest={
   format:'r62-guardian-v5-lab-stage-1',
   createdUtc:new Date().toISOString(),
   purpose:'offline-lab-staging-only',
   encryptedDatabaseSha256:db.sha256,
   recoveryProven:false,
   secretsVaultIncluded:false,
   entries:entries.map(({name,bytes,sha256})=>({name,bytes,sha256}))
  };
  fs.writeFileSync(path.join(tmp,'manifest.json'),JSON.stringify(manifest,null,2)+'\n',{flag:'wx',mode:0o600});
  // Re-check every staged file just before publication.
  for(const e of entries)if(hashFile(path.join(tmp,e.name))!==e.sha256)fail('STAGE_FINAL_VERIFY_FAILED');
  if(fs.existsSync(target))fail('TARGET_EXISTS_NO_OVERWRITE');
  fs.renameSync(tmp,target);
  published=true;
  return {mode,files:entries.length,total,targetCreated:true,componentRoles:6};
 }finally{
  // Only delete a staging folder generated by THIS process; never touch existing targets.
  if(!published)fs.rmSync(tmp,{recursive:true,force:true});
 }
}
function argvRead(argv){
 const a={};
 if(argv.length!==6)fail('USAGE');
 for(let i=0;i<argv.length;i+=2){
  if(!['--config','--lab-root','--mode'].includes(argv[i])||argv[i] in a)fail('USAGE');
  a[argv[i]]=argv[i+1];
 }
 if(typeof a['--config']!=='string'||typeof a['--lab-root']!=='string'||!['plan','stage'].includes(a['--mode']))fail('USAGE');
 return {cfg:parseConfig(fs.readFileSync(a['--config'],'utf8')),lab:a['--lab-root'],mode:a['--mode']};
}
function cli(argv){
 const opt=argvRead(argv);
 const result=prepare(opt);
 const report=['=== ROTA62 GUARDIAN V5 OFFLINE LAB STAGING ===',
  'MODE='+result.mode.toUpperCase(),
  'STATUS='+ (result.targetCreated?'STAGED_AND_HASH_VERIFIED':'PLAN_ONLY'),
  'SOURCE_COMPONENTS_GATE=7_OF_7',
  'COMPONENTS_STAGED=6_OF_7',
  'FILES_VERIFIED='+result.files,
  'BYTES_STAGED_OR_PLANNED='+result.total,
  'DESTINATION_CREATED='+(result.targetCreated?'YES':'NO'),
  'ENCRYPTED_DATABASE_COPIED='+(result.targetCreated?'YES':'NO'),
  'SECRETS_VAULT_COPIED=NO',
  'DATABASE_DECRYPTED=NO',
  'DATABASE_RESTORED=NO',
  'WEB_API_DEPLOYED=NO',
  'PRODUCTION_TOUCHED=NO',
  'RTO_4_TO_6_HOURS_VALIDATED=NO',
  'END_REPORT_OK'];
 console.log(report.join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{cli(process.argv.slice(2));}
 catch(e){
  const safe=new Set(['USAGE','INVALID_MODE','LAB_PATH_NOT_ABSOLUTE','LAB_CANNOT_BE_DISK_ROOT','LAB_INVALID',
   'LAB_SYMLINK_ANCESTOR','LAB_MARKER_INVALID','LAB_OVERLAPS_SOURCE','SEVEN_COMPONENTS_NOT_VERIFIED',
   'SYMLINK_BLOCKED','WRONG_COMPONENT_KIND','FILE_LIMIT','BYTE_LIMIT','SPECIAL_FILE_BLOCKED',
   'EMPTY_COMPONENT','DUPLICATE_PATH','DB_HASH_MISMATCH','SOURCE_SYMLINK','STAGED_HASH_MISMATCH',
   'SOURCE_CHANGED_DURING_COPY','STAGE_FINAL_VERIFY_FAILED','TARGET_EXISTS_NO_OVERWRITE']);
  console.log('=== ROTA62 GUARDIAN V5 OFFLINE LAB STAGING ===\nSTATUS=BLOCKED_'+(safe.has(e.message)?e.message:'REDACTED')+
   '\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

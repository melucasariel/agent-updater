#!/usr/bin/env node
// ROTA62 Guardian V5 — verify an already prepared OFFLINE recovery stage.
// No dependence on original source directories, passwords, Docker, or network.
// This validates bytes against an unsigned LOCAL manifest; not backup provenance.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';

const fail=s=>{throw Error(s);};
function hashFile(p){
 const h=crypto.createHash('sha256'),fd=fs.openSync(p,'r');
 try{
  const buf=Buffer.allocUnsafe(1024*1024);
  for(;;){const n=fs.readSync(fd,buf,0,buf.length,null);if(!n)break;h.update(buf.subarray(0,n));}
 }finally{fs.closeSync(fd);}
 return h.digest('hex');
}
function safeName(n){
 return typeof n==='string'&&n.length>0&&n.length<=600&&!path.isAbsolute(n)&&
  !n.includes('\\')&&!n.includes('\0')&&n.split('/').every(x=>x!==''&&x!=='.'&&x!=='..'&& !/[\x00-\x1f:]/.test(x));
}
function stagedFiles(root){
 const result=[],queue=[{p:root,rel:''}];let walked=0;
 while(queue.length){
  const current=queue.shift();
  for(const x of fs.readdirSync(current.p,{withFileTypes:true})){
   if(++walked>20000)fail('STAGE_LIMIT');
   const full=path.join(current.p,x.name),rel=path.posix.join(current.rel,x.name);
   const stat=fs.lstatSync(full);
   if(stat.isSymbolicLink())fail('SYMLINK_BLOCKED');
   if(stat.isDirectory())queue.push({p:full,rel});
   else if(stat.isFile()&&rel!=='manifest.json')result.push(rel);
   else if(!stat.isFile())fail('SPECIAL_FILE_BLOCKED');
  }
 }
 return result.sort();
}
export function verifyStage(dir){
 if(!path.isAbsolute(dir)||path.resolve(dir)===path.parse(dir).root)fail('INVALID_STAGE_DIR');
 if(!fs.lstatSync(dir).isDirectory()||fs.lstatSync(dir).isSymbolicLink())fail('INVALID_STAGE_DIR');
 if(fs.realpathSync(dir)!==path.resolve(dir))fail('STAGE_ANCESTOR_SYMLINK');
 const manifestFile=path.join(dir,'manifest.json');
 if(fs.lstatSync(manifestFile).isSymbolicLink())fail('SYMLINK_BLOCKED');
 const stat=fs.statSync(manifestFile);
 if(!stat.isFile()||stat.size>5*1024*1024)fail('INVALID_MANIFEST');
 let m;try{m=JSON.parse(fs.readFileSync(manifestFile,'utf8'));}catch{fail('INVALID_MANIFEST');}
 if(m?.format!=='r62-guardian-v5-lab-stage-1'||m.secretsVaultIncluded!==false||
  m.recoveryProven!==false||!Array.isArray(m.entries)||m.entries.length<6||m.entries.length>10000||
  !/^[a-f0-9]{64}$/i.test(m.encryptedDatabaseSha256||''))fail('INVALID_MANIFEST');
 const expected=new Map(),roles=new Set();let total=0;
 for(const x of m.entries){
  if(!x||!safeName(x.name)||!/^[a-f0-9]{64}$/i.test(x.sha256||'')||
   !Number.isSafeInteger(x.bytes)||x.bytes<0||expected.has(x.name))fail('INVALID_MANIFEST_ENTRY');
  const role=x.name.split('/')[0];
  if(!['database','web','api','storage','dns','config'].includes(role))fail('UNKNOWN_ROLE');
  if(role==='database'&&x.name!=='database/snapshot.r62db')fail('INVALID_DB_PATH');
  if(['dns','config'].includes(role)&&x.name!==role+'/snapshot')fail('INVALID_FILE_ROLE_PATH');
  expected.set(x.name,x);roles.add(role);total+=x.bytes;
  if(total>10*1024**3)fail('STAGE_BYTES_LIMIT');
 }
 if(roles.size!==6||[...expected.keys()].filter(x=>x.startsWith('database/')).length!==1)fail('MISSING_ROLE');
 const actual=stagedFiles(dir);
 if(actual.length!==expected.size||actual.some(x=>!expected.has(x)))fail('EXTRA_OR_MISSING_FILE');
 for(const name of actual){
  const entry=expected.get(name),full=path.join(dir,...name.split('/'));
  const st=fs.lstatSync(full);
  if(st.size!==entry.bytes||hashFile(full).toLowerCase()!==entry.sha256.toLowerCase())fail('HASH_MISMATCH');
 }
 if(expected.get('database/snapshot.r62db').sha256.toLowerCase()!==m.encryptedDatabaseSha256.toLowerCase())fail('DATABASE_HASH_MISMATCH');
 return {files:expected.size,bytes:total};
}
function cli(argv){
 if(argv.length!==2||argv[0]!=='--stage'||!argv[1])fail('USAGE');
 const r=verifyStage(argv[1]);
 console.log(['=== ROTA62 GUARDIAN V5 STAGE INDEPENDENT VERIFY ===',
  'STAGE_INTEGRITY=PASS',
  'FILES='+r.files,
  'BYTES='+r.bytes,
  'ROLES=6_OF_6',
  'ORIGINAL_SNAPSHOT_REQUIRED=NO',
  'MANIFEST_CRYPTOGRAPHICALLY_SIGNED=NO',
  'SECRETS_RESTORED=NO',
  'DATABASE_DECRYPTED=NO',
  'APPLICATION_STARTED=NO',
  'PRODUCTION_TOUCHED=NO',
  'RTO_4_TO_6_HOURS_VALIDATED=NO',
  'END_REPORT_OK'].join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{cli(process.argv.slice(2));}
 catch(e){
  const codes=['USAGE','INVALID_STAGE_DIR','STAGE_ANCESTOR_SYMLINK','SYMLINK_BLOCKED','STAGE_LIMIT',
   'SPECIAL_FILE_BLOCKED','INVALID_MANIFEST','INVALID_MANIFEST_ENTRY','UNKNOWN_ROLE','INVALID_DB_PATH',
   'INVALID_FILE_ROLE_PATH','STAGE_BYTES_LIMIT','MISSING_ROLE','EXTRA_OR_MISSING_FILE','HASH_MISMATCH',
   'DATABASE_HASH_MISMATCH'];
  console.log('=== ROTA62 GUARDIAN V5 STAGE INDEPENDENT VERIFY ===\nSTAGE_INTEGRITY=BLOCKED\nCODE='+
   (codes.includes(e.message)?e.message:'ERROR_REDACTED')+'\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

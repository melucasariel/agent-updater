#!/usr/bin/env node
// ROTA62 Guardian V5.2 — SAFE encrypted-backup provenance and restore-input gate.
// Reads only ciphertext and optional independently staged lab files.
// It NEVER decrypts, copies data, executes Docker/SQL, deploys or opens secrets.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {verifyStage} from './GuardianV5-VerifyStage.mjs';

const fail=s=>{throw Error(s);};
const MAX_ARCHIVE=1024*1024*1024;
const format='R62DB02';
function isFile(name){
 if(!path.isAbsolute(name))fail('NOT_ABSOLUTE_PATH');
 const info=fs.lstatSync(name);
 if(info.isSymbolicLink()||!info.isFile())fail('NOT_REGULAR_FILE');
 if(info.size<32||info.size>MAX_ARCHIVE)fail('ARCHIVE_SIZE_INVALID');
 return info;
}
function inspectCiphertext(name){
 const before=isFile(name);
 const h=crypto.createHash('sha256');
 const fd=fs.openSync(name,'r');
 let prefix=Buffer.alloc(0),size=0;
 try{
  const buf=Buffer.allocUnsafe(1024*1024);
  for(;;){
   const n=fs.readSync(fd,buf,0,buf.length,null);
   if(!n)break;
   if(!size)prefix=Buffer.from(buf.subarray(0,Math.min(n,8)));
   size+=n;
   if(size>MAX_ARCHIVE)fail('ARCHIVE_SIZE_INVALID');
   h.update(buf.subarray(0,n));
  }
 }finally{fs.closeSync(fd);}
 const after=isFile(name);
 if(size!==before.size||after.size!==before.size||after.mtimeMs!==before.mtimeMs)fail('ARCHIVE_CHANGED_DURING_READ');
 if(!prefix.toString('ascii').startsWith(format))fail('UNEXPECTED_ARCHIVE_MAGIC');
 return {sha256:h.digest('hex'),size,mtime:after.mtimeMs};
}
function options(argv){
 if(!argv.length||argv.length%2!==0)fail('USAGE');
 const args={};
 const allowed=new Set(['--archive','--reference-sha256','--stage','--copy-1','--copy-2']);
 for(let i=0;i<argv.length;i+=2){
  if(!allowed.has(argv[i])||args[argv[i]]!==undefined)fail('USAGE');
  args[argv[i]]=argv[i+1];
 }
 if(!args['--archive']||!args['--reference-sha256']||!/^[a-f0-9]{64}$/i.test(args['--reference-sha256']))fail('USAGE');
 if(args['--copy-2']&&!args['--copy-1'])fail('USAGE');
 return args;
}
export function review(o){
 const expected=o['--reference-sha256'].toLowerCase();
 const main=inspectCiphertext(o['--archive']);
 if(main.sha256!==expected)fail('CIPHERTEXT_HASH_MISMATCH');
 const copies=[main];
 for(const flag of ['--copy-1','--copy-2']){
  if(!o[flag])continue;
  const c=inspectCiphertext(o[flag]);
  if(c.sha256!==expected)fail('COPY_HASH_MISMATCH');
  copies.push(c);
 }
 let stage=null;
 if(o['--stage']){
  stage=verifyStage(o['--stage']);
  const manifest=JSON.parse(fs.readFileSync(path.join(o['--stage'],'manifest.json'),'utf8'));
  if(manifest.encryptedDatabaseSha256.toLowerCase()!==expected)fail('STAGE_ARCHIVE_MISMATCH');
 }
 const snapshots=new Set(copies.map(x=>x.sha256));
 return {archive:main,copies:copies.length,uniqueSnapshots:snapshots.size,stage};
}
export function main(argv){
 const o=options(argv);
 const result=review(o);
 const report=[
  '=== ROTA62 GUARDIAN V5.2 ENCRYPTED RECOVERY INPUT GATE ===',
  'READ_ONLY=YES',
  'ARCHIVE_FORMAT_HEADER=R62DB02',
  'CIPHERTEXT_SHA256_VERIFIED=YES',
  'CIPHERTEXT_BYTES='+result.archive.size,
  'IDENTICAL_COPIES_FOUND='+result.copies,
  'DISTINCT_RECOVERY_POINTS='+result.uniqueSnapshots,
  'STAGED_LAB_INTEGRITY='+(result.stage?'HASHES_VERIFIED':'NOT_SUPPLIED'),
  'STAGED_LAB_FILES='+(result.stage?result.stage.files:'NOT_CHECKED'),
  'CRYPTOGRAPHIC_AUTHENTICATION_PERFORMED=NO',
  'BACKUP_AGE_PROVES_FRESH_CAPTURE=NO',
  'SUPABASE_ROLES_ACL_PROVENANCE=NO',
  'DATABASE_RESTORED=NO',
  'WEB_API_STORAGE_RESTORED=NO',
  'SECRETS_USED=NO',
  'PRODUCTION_TOUCHED=NO',
  'RTO_4_TO_6_HOURS_PROVEN=NO',
  'RECOVERY_DECISION=BLOCKED_PENDING_AUTHENTICATED_DECRYPT_AND_CLEAN_RESTORE',
  'END_REPORT_OK'
 ];
 console.log(report.join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main(process.argv.slice(2));}
 catch(e){
  const codes=['USAGE','NOT_ABSOLUTE_PATH','NOT_REGULAR_FILE','ARCHIVE_SIZE_INVALID',
   'ARCHIVE_CHANGED_DURING_READ','UNEXPECTED_ARCHIVE_MAGIC','CIPHERTEXT_HASH_MISMATCH',
   'COPY_HASH_MISMATCH','STAGE_ARCHIVE_MISMATCH'];
  console.log('=== ROTA62 GUARDIAN V5.2 ENCRYPTED RECOVERY INPUT GATE ===\nSTATUS=BLOCKED_'+
   (codes.includes(e.message)?e.message:'REDACTED')+
   '\nSECRETS_USED=NO\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

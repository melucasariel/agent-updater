#!/usr/bin/env node
// Guardian V5.3 — AUTHENTICATED R62DB02 verifier, from reviewed backup-postgres.mjs v1.4.4.
// Never stores plaintext, never runs pg_restore, Docker, SQL, cloud APIs or uploads.
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {pipeline} from 'node:stream/promises';
import {Transform,Writable} from 'node:stream';
import {fileURLToPath} from 'node:url';

const MAGIC=Buffer.from('R62DB02\n','ascii');
const KDF={N:32768,r:8,p:1,maxmem:128*1024*1024};
const MAX_CIPHER=1024*1024*1024;
const fail=s=>{throw Error(s);};
const hex=(x,n)=>typeof x==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(x);
const checksum=file=>new Promise((ok,bad)=>{
 const h=crypto.createHash('sha256'),r=fs.createReadStream(file);
 r.on('error',bad);r.on('data',c=>h.update(c));r.on('end',()=>ok(h.digest('hex')));
});
function headerInfo(file){
 if(!path.isAbsolute(file))fail('INVALID_PATH');
 const st=fs.lstatSync(file);
 if(!st.isFile()||st.isSymbolicLink()||st.size<64||st.size>MAX_CIPHER)fail('INVALID_ARCHIVE');
 let fd;try{
  fd=fs.openSync(file,'r');
  const pre=Buffer.alloc(12);
  if(fs.readSync(fd,pre,0,12,0)!==12||!pre.subarray(0,8).equals(MAGIC))fail('BAD_MAGIC');
  const len=pre.readUInt32BE(8);
  if(len<11||len>4096||st.size<=12+len+16)fail('INVALID_HEADER_LENGTH');
  const raw=Buffer.alloc(len);
  if(fs.readSync(fd,raw,0,len,12)!==len)fail('TRUNCATED_HEADER');
  let head;try{head=JSON.parse(raw.toString('utf8'));}catch{fail('INVALID_HEADER_JSON');}
  if(head?.schema!==2||head?.format!=='pg_dump_custom'||head?.cipher!=='AES-256-GCM'||
   head?.kdf!=='scrypt'||head?.N!==KDF.N||head?.r!==KDF.r||head?.p!==KDF.p||
   !hex(head.salt,32)||!hex(head.nonce,24))fail('UNSUPPORTED_HEADER');
  const tag=Buffer.alloc(16);
  if(fs.readSync(fd,tag,0,16,st.size-16)!==16)fail('MISSING_TAG');
  return {preamble:Buffer.concat([pre,raw]),tag,header:head,start:12+len,end:st.size-17,bytes:st.size,mtimeMs:st.mtimeMs};
 }finally{if(fd!==undefined)fs.closeSync(fd);}
}
export async function authenticate(file,expectedSha256,password){
 if(!hex(expectedSha256?.toLowerCase(),64))fail('EXPECTED_SHA_INVALID');
 if(typeof password!=='string'||password.length<1)fail('EMPTY_PASSWORD');
 const meta=headerInfo(file);
 const before=await checksum(file);
 if(before!==expectedSha256.toLowerCase())fail('ENCRYPTED_SHA_MISMATCH');
 const key=crypto.scryptSync(password,Buffer.from(meta.header.salt,'hex'),32,KDF);
 let count=0;let first=Buffer.alloc(0);
 const h=crypto.createHash('sha256');
 try{
  const decryptor=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(meta.header.nonce,'hex'));
  decryptor.setAAD(meta.preamble);
  decryptor.setAuthTag(meta.tag);
  const monitor=new Transform({transform(buf,enc,cb){
   count+=buf.length;
   if(count>MAX_CIPHER)return cb(Error('PLAINTEXT_SIZE_LIMIT'));
   h.update(buf);
   if(first.length<5)first=Buffer.concat([first,buf.subarray(0,5-first.length)]);
   cb(null,buf);
  }});
  const sink=new Writable({write(buf,enc,cb){cb();}});
  try{
   await pipeline(fs.createReadStream(file,{start:meta.start,end:meta.end}),decryptor,monitor,sink);
  }catch{
   fail('AUTHENTICATION_FAILED');
  }
 }finally{key.fill(0);}
 // A decrypted prefix is not enough: this check occurs ONLY after successful GCM finalization.
 if(!first.equals(Buffer.from('PGDMP'))||count<32)fail('NOT_PG_CUSTOM_DUMP');
 const after=await checksum(file);
 const stat=fs.lstatSync(file);
 if(after!==before||stat.size!==meta.bytes||stat.mtimeMs!==meta.mtimeMs)fail('CIPHERTEXT_CHANGED');
 return {bytes:count,encryptedBytes:meta.bytes,plainSha256:h.digest('hex')};
}
async function secretPrompt(){
 if(!process.stdin.isTTY||typeof process.stdin.setRawMode!=='function')fail('TTY_REQUIRED');
 return await new Promise((resolve,reject)=>{
  let password='',done=false;
  const prev=process.stdin.isRaw;
  function end(error){
   if(done)return;done=true;
   process.stdin.off('data',onData);
   process.stdin.setRawMode(Boolean(prev));
   process.stdin.pause();
   process.stdout.write('\n');
   if(error)reject(error);else resolve(password);
  }
  function onData(c){
   for(const chr of c.toString('utf8')){
    if(chr==='\x03'){end(Error('CANCELLED'));return;}
    if(chr==='\r'||chr==='\n'){end();return;}
    if(chr==='\x7f'||chr==='\b'){
     if(password.length){password=password.slice(0,-1);process.stdout.write('\b \b');}
     continue;
    }
    if(chr>=' '&&password.length<1024){password+=chr;process.stdout.write('*');}
   }
  }
  process.stdout.write('Senha do backup (somente neste terminal): ');
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.on('data',onData);
 });
}
function parse(args){
 if(![4,6].includes(args.length)||args[0]!=='--archive'||args[2]!=='--expected-sha256')fail('USAGE');
 if(args.length===6&&(args[4]!=='--report-file'||!path.isAbsolute(args[5])))fail('USAGE');
 if(!path.isAbsolute(args[1])||!hex(args[3]?.toLowerCase(),64))fail('USAGE');
 return {file:args[1],sha:args[3],reportFile:args.length===6?args[5]:null};
}
export async function main(args){
 const p=parse(args);
 // Cheap integrity and source check BEFORE password prompt.
 const metadata=headerInfo(p.file);
 const found=await checksum(p.file);
 if(found!==p.sha.toLowerCase())fail('ENCRYPTED_SHA_MISMATCH');
 const pass=await secretPrompt();
 const data=await authenticate(p.file,p.sha,pass);
 const report=['=== ROTA62 GUARDIAN V5.3 AES-GCM AUTHENTICATION ===',
  'SOURCE_FORMAT=R62DB02','EXPECTED_SHA256_MATCH=YES','AES_GCM_TAG_AUTHENTICATED=YES',
  'DECRYPTED_PG_CUSTOM_HEADER=YES','DECRYPTED_BYTES='+data.bytes,
  'DECRYPTED_SHA16='+data.plainSha256.slice(0,16).toUpperCase(),
  'ENCRYPTED_BYTES='+metadata.bytes,
  'PLAINTEXT_FILE_CREATED=NO','DATABASE_RESTORED=NO','ROLES_ACL_RESTORED=NO',
  'NO_DOCKER_SQL_CLOUD_OPERATIONS=YES','PRODUCTION_TOUCHED=NO',
  'RECOVERY_RTO_PROVEN=NO','END_REPORT_OK'].join('\n');
 if(p.reportFile)fs.writeFileSync(p.reportFile,report+'\n',{flag:'wx',mode:0o600});
 console.log(report);
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 main(process.argv.slice(2)).catch(e=>{
  const known=['USAGE','INVALID_PATH','INVALID_ARCHIVE','BAD_MAGIC','INVALID_HEADER_LENGTH',
   'TRUNCATED_HEADER','INVALID_HEADER_JSON','UNSUPPORTED_HEADER','MISSING_TAG',
   'EXPECTED_SHA_INVALID','EMPTY_PASSWORD','ENCRYPTED_SHA_MISMATCH','AUTHENTICATION_FAILED',
   'PLAINTEXT_SIZE_LIMIT','NOT_PG_CUSTOM_DUMP','CIPHERTEXT_CHANGED','TTY_REQUIRED','CANCELLED'];
  const safe='=== ROTA62 GUARDIAN V5.3 AES-GCM AUTHENTICATION ===\nSTATUS=BLOCKED_'+
   (known.includes(e.message)?e.message:'ERROR_REDACTED')+
   '\nPLAINTEXT_FILE_CREATED=NO\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK';
  const a=process.argv.slice(2);
  if(a.length===6&&a[4]==='--report-file'&&path.isAbsolute(a[5])){
   try{fs.writeFileSync(a[5],safe+'\n',{flag:'wx',mode:0o600});}catch{}
  }
  console.log(safe);
  process.exitCode=2;
 });
}

#!/usr/bin/env node
// ROTA62 Guardian v0.4 - read-only authenticated verification of R62DB02.
// Compatible with the source backup-postgres.mjs AES-GCM/scrypt structure.
// No writes to database, no plaintext dump on disk, no network, no secrets in logs.
import fs from 'node:fs';
import crypto from 'node:crypto';
import { Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { stdin, stdout } from 'node:process';
import { spawnSync } from 'node:child_process';

const MAGIC=Buffer.from('R62DB02\n','ascii');
const PARAMS={N:32768,r:8,p:1,maxmem:128*1024*1024};
const EXPECTED_SHA='35fcccd54db5d42729eff95227133d0875d6fc7f730c881ba486f87f46f038ea';
const EXPECTED_SIZE=5287976;
const report=['=== ROTA62 BACKUP AES VERIFY v0.4 ===','[MODO] READ_ONLY_NO_RESTORE_NO_PLAINTEXT_FILE'];
const add=s=>report.push(s);
function fail(code){throw Error(code)}
function safeCode(e){const m=String(e?.message||'');return /^[A-Z0-9_]{2,80}$/.test(m)?m:'AES_AUTHENTICATION_FAILED_OR_BAD_PASSPHRASE'}
function envelope(file) {
 const stat=fs.statSync(file);
 if(!stat.isFile()||stat.size!==EXPECTED_SIZE)fail('FILE_SIZE_MISMATCH');
 const fd=fs.openSync(file,'r');
 try{
  const pre=Buffer.alloc(12);
  if(fs.readSync(fd,pre,0,12,0)!==12 || !pre.subarray(0,8).equals(MAGIC))fail('R62DB_MAGIC_INVALID');
  const len=pre.readUInt32BE(8);
  if(len<50||len>4096)fail('HEADER_LENGTH_INVALID');
  const raw=Buffer.alloc(len);
  if(fs.readSync(fd,raw,0,len,12)!==len)fail('HEADER_TRUNCATED');
  const h=JSON.parse(raw.toString('utf8'));
  if(h.schema!==2 || h.format!=='pg_dump_custom' || h.cipher!=='AES-256-GCM' || h.kdf!=='scrypt' ||
     h.N!==32768 || h.r!==8 || h.p!==1 || !/^[a-f0-9]{32}$/.test(h.salt) || !/^[a-f0-9]{24}$/.test(h.nonce))fail('BACKUP_CRYPTO_METADATA_INVALID');
  const tag=Buffer.alloc(16);
  if(fs.readSync(fd,tag,0,16,stat.size-16)!==16)fail('AUTH_TAG_MISSING');
  const start=12+len,end=stat.size-17;
  if(end<start)fail('ENCRYPTED_PAYLOAD_MISSING');
  return {header:h,preamble:Buffer.concat([pre,raw]),tag,start,end};
 }finally{fs.closeSync(fd)}
}
async function hashFile(file){
 const h=crypto.createHash('sha256');
 for await(const buf of fs.createReadStream(file))h.update(buf);
 return h.digest('hex');
}
async function askSecret(){
 if(!stdin.isTTY || typeof stdin.setRawMode!=='function')fail('INTERACTIVE_TERMINAL_REQUIRED');
 stdout.write('Digite a SENHA DO BACKUP (oculta; nao e a senha do PostgreSQL): ');
 let secret='';
 const oldRaw=stdin.isRaw;
 return await new Promise((resolve,reject)=>{
  function finish(err){
   stdin.off('data',onData);stdin.setRawMode(Boolean(oldRaw));stdin.pause();stdout.write('\n');
   err?reject(err):resolve(secret);
  }
  function onData(chunk){
   for(const c of chunk.toString('utf8')){
    if(c==='\u0003'){finish(Error('CANCELLED'));return;}
    if(c==='\r'||c==='\n'){finish();return;}
    if(c==='\b'||c==='\u007f'){secret=secret.slice(0,-1);continue;}
    if(c==='\u001b')continue;
    if(c>=' '&&secret.length<1024)secret+=c;
   }
  }
  stdin.setRawMode(true);stdin.resume();stdin.on('data',onData);
 });
}
async function authenticate(file,pass,env){
 const key=crypto.scryptSync(pass,Buffer.from(env.header.salt,'hex'),32,PARAMS);
 let count=0,first=Buffer.alloc(0);
 const digest=crypto.createHash('sha256');
 try{
  const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(env.header.nonce,'hex'));
  decipher.setAAD(env.preamble);
  decipher.setAuthTag(env.tag);
  const sink=new Writable({write(chunk,unused,done){
   count+=chunk.length;digest.update(chunk);
   if(first.length<5)first=Buffer.concat([first,chunk.subarray(0,5-first.length)]);
   done();
  }});
  await pipeline(fs.createReadStream(file,{start:env.start,end:env.end}),decipher,sink);
  if(!first.equals(Buffer.from('PGDMP','ascii')))fail('POSTGRES_CUSTOM_HEADER_INVALID');
  return {bytes:count,sha256:digest.digest('hex')};
 }finally{key.fill(0);}
}
function copyReport(){
 try{
  if(process.platform!=='win32')return;
  const r=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command','$input | Set-Clipboard'],{
   input:report.join('\r\n'),encoding:'utf8',windowsHide:true,timeout:12000
  });
  if(r.status===0)add('[OK] RELATORIO_COPIADO');
 }catch{}
}
async function selftest(){
 const b=Buffer.from('PGDMP'+('synthetic-test-'.repeat(30)));
 const h={schema:2,format:'pg_dump_custom',cipher:'AES-256-GCM',kdf:'scrypt',N:32768,r:8,p:1,salt:crypto.randomBytes(16).toString('hex'),nonce:crypto.randomBytes(12).toString('hex')};
 const raw=Buffer.from(JSON.stringify(h));
 const length=Buffer.alloc(4);length.writeUInt32BE(raw.length,0);
 const pre=Buffer.concat([MAGIC,length,raw]);
 const key=crypto.scryptSync('LOCAL_TEST_ONLY',Buffer.from(h.salt,'hex'),32,PARAMS);
 const cipher=crypto.createCipheriv('aes-256-gcm',key,Buffer.from(h.nonce,'hex'));cipher.setAAD(pre);
 const encrypted=Buffer.concat([cipher.update(b),cipher.final(),cipher.getAuthTag()]);
 const { mkdtempSync,writeFileSync,rmSync }=fs;
 const {tmpdir}=await import('node:os');const {join}=await import('node:path');
 const dir=mkdtempSync(join(tmpdir(),'r62-aes-selftest-'));const file=join(dir,'sample.r62db');
 try{
  writeFileSync(file,Buffer.concat([pre,encrypted]));
  // Envelope and authentication selftest with expected-size check disabled for fixture only.
  const x=fs.readFileSync(file);
  const parsed={header:h,preamble:pre,tag:x.subarray(x.length-16),start:pre.length,end:x.length-17};
  const pass=await authenticate(file,'LOCAL_TEST_ONLY',parsed);
  if(pass.bytes!==b.length||pass.sha256!==crypto.createHash('sha256').update(b).digest('hex'))fail('SELFTEST_PLAINTEXT_MISMATCH');
  let rejected=false;
  try{await authenticate(file,'WRONG_PASS',parsed)}catch{rejected=true}
  if(!rejected)fail('SELFTEST_WRONG_PASSWORD_ACCEPTED');
  const tampered=Buffer.from(x);tampered[tampered.length-18]^=1;writeFileSync(file,tampered);
  rejected=false;
  try{await authenticate(file,'LOCAL_TEST_ONLY',parsed)}catch{rejected=true}
  if(!rejected)fail('SELFTEST_TAMPER_ACCEPTED');
  console.log('AES_SELFTEST=PASS');
 }finally{key.fill(0);rmSync(dir,{recursive:true,force:true});}
}
async function main(){
 if(process.argv[2]==='--selftest'){await selftest();return;}
 const file=process.argv[2];
 if(!file||!fs.existsSync(file))fail('BACKUP_FILE_NOT_ACCESSIBLE');
 if((await hashFile(file))!==EXPECTED_SHA)fail('ORIGINAL_SHA256_MISMATCH');
 add('[OK] ENCRYPTED_BACKUP_SHA256_MATCH');
 const env=envelope(file);
 add('[OK] ORIGINAL_AES_GCM_ENVELOPE_VALID');
 let pass='';
 try{
  pass=await askSecret();
  if(!pass)fail('EMPTY_BACKUP_PASSWORD');
  const restored=await authenticate(file,pass,env);
  add('[APROVADO] AES_256_GCM_AUTHENTICATED');
  add('[OK] POSTGRES_PGDMP_MAGIC');
  add('PLAINTEXT_BYTES='+restored.bytes);
  add('PLAINTEXT_SHA256='+restored.sha256);
  add('[LIMITE] Database restore, roles, ACLs, web and API not tested');
 }finally{pass='';}
}
let ok=true;
try{await main()}catch(e){ok=false;add('[BLOQUEADO] '+safeCode(e));}
if(process.argv[2]!=='--selftest'){
 copyReport();
 for(const row of report)console.log(row);
}
if(!ok)process.exitCode=1;

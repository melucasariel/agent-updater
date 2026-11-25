#!/usr/bin/env node
// ROTA62 CLEAN6 password + AES-256-GCM authentication check ONLY.
// Based on prior verified guardian-restore-stage1.mjs decryptTo implementation.
// No database connection, no plaintext file, no restore, no external network.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {Writable,Transform} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {spawnSync} from 'node:child_process';
import {stdin,stdout} from 'node:process';

const report=['=== ROTA62 CLEAN6 AUTHENTICATED BACKUP CHECK v0.7.6 ===',
'[MODO] NO_SQL_NO_RESTORE_NO_PLAINTEXT_FILE_NO_NETWORK'];
const expected='35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA';
const archiveName='R62_PG_20261124T053055_990Z_1aff95.r62db';
const totalBytes=5287976;
const plainBytes=5287733;
function assert(ok,msg){if(!ok)throw Error(msg)}
function log(msg){report.push(msg);stdout.write(msg+'\n')}
function secret(prompt){
 assert(stdin.isTTY && typeof stdin.setRawMode==='function','INTERACTIVE_TTY_REQUIRED');
 return new Promise((resolve,reject)=>{
  let value='';const wasRaw=stdin.isRaw;
  const finish=(error)=>{
   stdin.off('data',handle);
   stdin.setRawMode(Boolean(wasRaw));stdin.pause();stdout.write('\n');
   if(error)reject(error);else resolve(value);
  };
  const handle=(chunk)=>{
   for(const char of chunk.toString('utf8')){
    if(char==='\x03'){finish(Error('CANCELED'));return}
    if(char==='\r'||char==='\n'){finish();return}
    if(char==='\x7f'||char==='\b'){if(value){value=value.slice(0,-1);stdout.write('\b \b')}continue}
    if(char==='\x1b')continue;
    if(char>=' '&&value.length<1024){value+=char;stdout.write('*')}
   }
  };
  stdin.setRawMode(true);stdin.resume();stdin.on('data',handle);stdout.write(prompt);
 });
}
function header(file){
 const fd=fs.openSync(file,'r');
 let p,hraw,tag;
 try{
  p=Buffer.alloc(12);
  assert(fs.readSync(fd,p,0,12,0)===12,'HEADER_TRUNCATED');
  assert(p.subarray(0,8).equals(Buffer.from('R62DB02\n','ascii')),'HEADER_MAGIC_UNEXPECTED');
  const len=p.readUInt32BE(8);
  assert(len>10&&len<=4096,'HEADER_LENGTH_UNEXPECTED');
  hraw=Buffer.alloc(len);
  assert(fs.readSync(fd,hraw,0,len,12)===len,'HEADER_BODY_TRUNCATED');
  tag=Buffer.alloc(16);
  assert(fs.readSync(fd,tag,0,16,totalBytes-16)===16,'AUTH_TAG_MISSING');
 }finally{fs.closeSync(fd)}
 const h=JSON.parse(hraw.toString('utf8'));
 assert(h.schema===2&&h.cipher==='AES-256-GCM'&&h.kdf==='scrypt'
   &&h.N===32768&&h.r===8&&h.p===1,'CRYPTO_HEADER_UNEXPECTED');
 assert(typeof h.salt==='string'&&/^[0-9a-f]{32}$/.test(h.salt)
   &&typeof h.nonce==='string'&&/^[0-9a-f]{24}$/.test(h.nonce),'CRYPTO_PARAMS_INVALID');
 return {h,preamble:Buffer.concat([p,hraw]),tag,start:12+hraw.length,end:totalBytes-17};
}
async function authenticate(file,password){
 const a=header(file);
 const key=crypto.scryptSync(password,Buffer.from(a.h.salt,'hex'),32,{N:32768,r:8,p:1,maxmem:128*1024*1024});
 const cipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(a.h.nonce,'hex'));
 key.fill(0);
 cipher.setAAD(a.preamble);cipher.setAuthTag(a.tag);
 let bytes=0,prefix=Buffer.alloc(0);
 const count=new Transform({transform(data,encoding,callback){
  bytes+=data.length;
  if(prefix.length<5)prefix=Buffer.concat([prefix,data.subarray(0,5-prefix.length)]);
  callback(null,data);
 }});
 const discard=new Writable({write(chunk,encoding,callback){callback()}});
 try {
  await pipeline(fs.createReadStream(file,{start:a.start,end:a.end}),cipher,count,discard);
 }catch{throw Error('AUTHENTICATION_FAILED_OR_CORRUPT')}
 assert(prefix.equals(Buffer.from('PGDMP','ascii')),'PGDMP_MAGIC_MISMATCH');
 assert(bytes===plainBytes,'PLAINTEXT_LENGTH_MISMATCH');
 return bytes;
}
async function main(){
 const file=process.argv[2];
 assert(file&&fs.existsSync(file)&&fs.statSync(file).isFile(),'BACKUP_FILE_MISSING');
 assert(file.split(/[\\/]/).pop()===archiveName,'BACKUP_FILENAME_UNEXPECTED');
 assert(fs.statSync(file).size===totalBytes,'BACKUP_SIZE_UNEXPECTED');
 const dig=crypto.createHash('sha256');
 for await(const chunk of fs.createReadStream(file))dig.update(chunk);
 assert(dig.digest('hex').toUpperCase()===expected,'BACKUP_SHA256_UNEXPECTED');
 log('[OK] ORIGINAL_ENCRYPTED_BACKUP_SHA256_VERIFIED');
 const h=header(file);
 assert(h.start<h.end,'BACKUP_PAYLOAD_INVALID');
 log('[OK] R62DB02_AES256_GCM_SCRYPT_FORMAT_VERIFIED');
 const pwd=await secret('Senha do backup ROTA62 (somente local): ');
 assert(pwd.length>0,'EMPTY_PASSWORD');
 // GCM authentication completes before reporting success. No plaintext persistence.
 await authenticate(file,pwd);
 log('[OK] AES256_GCM_TAG_AUTHENTICATED');
 log('[OK] PGDMP_HEADER_AND_PLAINTEXT_SIZE_VERIFIED');
 log('[APROVADO] BACKUP_DECRYPTION_AUTHENTICATED_NO_DATABASE_CHANGES');
 log('[LIMITE] No SQL, no restore; plaintext streamed directly to discard in RAM');
 log('[NEXT] PREPARE_ROLE_EXTENSION_AWARE_SEPARATE_TEST_DB_RESTORE');
}
try{await main();process.exitCode=0}
catch(e){
 const msg=String(e?.message||'UNKNOWN');
 log('[BLOQUEADO] CODIGO='+(/^[A-Z0-9_]{3,100}$/.test(msg)?msg:'LOCAL_ERROR_REDACTED'));
 process.exitCode=1;
}finally{
 const copy=report.join('\r\n');
 if(process.platform==='win32'){
  try{spawnSync('clip.exe',[],{input:copy,encoding:'utf8',windowsHide:true,timeout:5000})}catch{}
 }
 stdout.write('[INFO] RELATORIO_SEM_SENHA_COPIADO_PARA_AREA_DE_TRANSFERENCIA\n');
}

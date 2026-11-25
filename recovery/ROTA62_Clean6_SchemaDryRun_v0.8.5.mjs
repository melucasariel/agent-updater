#!/usr/bin/env node
// ROTA62 CLEAN6 v0.8.5. Read-only PostgreSQL custom dump TOC inspection.
// Authenticates original R62DB02 AES-256-GCM first; then streams PGDMP to pg_restore --list.
// No plaintext dump files, SQL, database writes, role changes, network, or secrets in report.
import fs from 'node:fs';
import crypto from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
import {stdin,stdout} from 'node:process';
import {Transform,Writable} from 'node:stream';
import {pipeline} from 'node:stream/promises';

const FILENAME='R62_PG_20261124T053055_990Z_1aff95.r62db';
const SHA='35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA';
const SIZE=5287976;
const PLAIN=5287733;
const SERVER='rota62_guardian_clean6_direct_pg';
const reports=['=== ROTA62 CLEAN6 SCHEMA SQL DRY RUN v0.8.5 ===','[MODO] READ_ONLY_AUTHENTICATED_TOC_NO_RESTORE_NO_SQL'];
function out(s){reports.push(s);stdout.write(s+'\n')}
function req(x,s){if(!x)throw Error(s)}
function safeCode(s){return /^[A-Z0-9_]{3,100}$/.test(s)?s:'LOCAL_ERROR_REDACTED'}
function docker(args){
 const p=spawnSync('docker',args,{encoding:'utf8',windowsHide:true,timeout:20000,maxBuffer:1024*1024});
 req(!p.error&&p.status===0,'DOCKER_READ_FAILED');return p.stdout.trim();
}
function checkDocker(){
 const s=JSON.parse(docker(['inspect',SERVER]))[0];
 const c=JSON.parse(docker(['inspect','rota62_guardian_clean6_pg']))[0];
 req(s?.State?.Running===true && c?.State?.Running===false,'DESTINATION_STATE_UNEXPECTED');
 req(s?.HostConfig?.NetworkMode==='none' && s?.Config?.User==='postgres','DESTINATION_SECURITY_MISMATCH');
 req(s.Image===c.Image && /^sha256:[a-f0-9]{64}$/.test(s.Image),'DESTINATION_IMAGE_MISMATCH');
 req(s.Mounts?.length===1&&s.Mounts[0]?.Name==='rota62_guardian_clean6_data','DESTINATION_VOLUME_MISMATCH');
 req(Object.keys(s.HostConfig?.PortBindings||{}).length===0,'DESTINATION_PORT_PUBLISHED');
 const v=docker(['exec','--user','postgres',SERVER,'pg_restore','--version']);
 req(/PostgreSQL\)\s+17\./.test(v),'PG_RESTORE_17_MISSING');
 out('[OK] CLEAN6_ISOLATED_PG_RESTORE_17_VERIFIED');
}
async function choosePassword(){
 req(stdin.isTTY&&typeof stdin.setRawMode==='function','INTERACTIVE_TERMINAL_REQUIRED');
 return await new Promise((resolve,reject)=>{
  let value='';let completed=false;const old=stdin.isRaw;
  function finish(err){if(completed)return;completed=true;stdin.off('data',read);
   stdin.setRawMode(Boolean(old));stdin.pause();stdout.write('\n');err?reject(err):resolve(value)}
  function read(buf){for(const ch of buf.toString('utf8')){
   if(ch==='\x03'){finish(Error('CANCELED'));return}
   if(ch==='\r'||ch==='\n'){finish();return}
   if(ch==='\b'||ch==='\x7f'){if(value.length){value=value.slice(0,-1);stdout.write('\b \b')}continue}
   if(ch==='\x1b')continue;
   if(ch>=' '&&value.length<1024){value+=ch;stdout.write('*')}
  }}
  stdin.setRawMode(true);stdin.resume();stdin.on('data',read);stdout.write('Senha do backup (somente local): ');
 });
}
function parseHeader(file){
 const fd=fs.openSync(file,'r');let p,b,tag;
 try{
  p=Buffer.alloc(12);
  req(fs.readSync(fd,p,0,12,0)===12,'BACKUP_HEADER_TRUNCATED');
  req(p.subarray(0,8).equals(Buffer.from('R62DB02\n','ascii')),'BACKUP_FORMAT_INVALID');
  let len=p.readUInt32BE(8);req(len>10&&len<=4096,'BACKUP_HEADER_LENGTH_INVALID');
  b=Buffer.alloc(len);req(fs.readSync(fd,b,0,len,12)===len,'BACKUP_HEADER_BODY_TRUNCATED');
  tag=Buffer.alloc(16);req(fs.readSync(fd,tag,0,16,SIZE-16)===16,'BACKUP_TAG_MISSING');
 }finally{fs.closeSync(fd)}
 const h=JSON.parse(b.toString('utf8'));
 req(h.schema===2&&h.cipher==='AES-256-GCM'&&h.kdf==='scrypt'&&h.N===32768&&h.r===8&&h.p===1,'BACKUP_CRYPTO_FORMAT_MISMATCH');
 req(/^[0-9a-f]{32}$/.test(h.salt)&&/^[0-9a-f]{24}$/.test(h.nonce),'BACKUP_CRYPTO_PARAMS_MISMATCH');
 return {h,preamble:Buffer.concat([p,b]),tag,start:12+b.length,end:SIZE-17};
}
async function decrypt(file,password,sink){
 const a=parseHeader(file);
 const key=crypto.scryptSync(password,Buffer.from(a.h.salt,'hex'),32,{N:32768,r:8,p:1,maxmem:128*1024*1024});
 const dec=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(a.h.nonce,'hex'));
 key.fill(0);
 dec.setAAD(a.preamble);dec.setAuthTag(a.tag);
 let len=0,first=Buffer.alloc(0);
 const monitor=new Transform({transform(part,_,next){
  len+=part.length;
  if(first.length<5)first=Buffer.concat([first,part.subarray(0,5-first.length)]);
  next(null,part);
 }});
 await pipeline(fs.createReadStream(file,{start:a.start,end:a.end}),dec,monitor,sink);
 req(len===PLAIN&&first.equals(Buffer.from('PGDMP','ascii')),'PGDMP_PAYLOAD_INVALID');
}
async function inspectSchemaSql(file,password){
 // pg_restore emits SQL to stdout only; no -d/--dbname is passed.
 // SQL never gets executed, persisted, printed or copied.
 const args=['exec','-i','--user','postgres',SERVER,'pg_restore','--schema-only','--no-owner','--no-acl','--file=-'];
 const child=spawn('docker',args,{windowsHide:true,stdio:['pipe','pipe','pipe']});
 let sql='',errors='',overflow=false;
 child.stdout.on('data',part=>{
  if(sql.length+part.length<16000000)sql+=part.toString('utf8');
  else{overflow=true;child.kill()}
 });
 child.stderr.on('data',part=>{errors=(errors+part.toString('utf8')).slice(-2000)});
 const exit=new Promise(resolve=>{
  child.once('error',()=>resolve({code:-1}));
  child.once('close',(code,signal)=>resolve({code,signal}));
 });
 let pipeErr;
 try{await decrypt(file,password,child.stdin)}catch(e){pipeErr=e}
 let timeout;
 const status=await Promise.race([exit,new Promise(resolve=>{
  timeout=setTimeout(()=>{child.kill();resolve({timeout:true})},60000)
 })]);
 clearTimeout(timeout);
 req(!status.timeout,'SCHEMA_DRYRUN_TIMEOUT');
 req(!overflow,'SCHEMA_SQL_OVERFLOW');
 req(status.code===0,'SCHEMA_PG_RESTORE_EXIT_FAILED');
 req(sql.includes('PostgreSQL database dump')&&sql.length>3000,'SCHEMA_SQL_OUTPUT_INVALID');
 // A successful pg_restore may terminate stdin early, after catalog/schema reading.
 if(pipeErr)out('[INFO] SQL_DRYRUN_STDIN_CLOSED_AFTER_VALID_OUTPUT');
 out('[OK] PG_RESTORE_SCHEMA_ONLY_GENERATED_WITHOUT_DB_CONNECTION');
 // Match only target DDL keywords; never output SQL text.
 const ext=[...sql.matchAll(/CREATE\s+EXTENSION\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"([^"]+)"|([a-zA-Z_][a-zA-Z0-9_-]*))/gi)]
   .map(m=>(m[1]||m[2]).toLowerCase());
 const schemas=[...sql.matchAll(/CREATE\s+SCHEMA\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:"([^"]+)"|([a-zA-Z_][a-zA-Z0-9_]*))/gi)]
   .map(m=>(m[1]||m[2]).toLowerCase());
 const extSet=new Set(ext),schSet=new Set(schemas);
 const expected=new Set(['pg_cron','pg_net','pg_stat_statements','pgcrypto','supabase_vault','uuid-ossp']);
 req(extSet.size===6&&[...expected].every(x=>extSet.has(x)),'EXPECTED_EXTENSION_DDL_NOT_FOUND');
 req(schSet.size>=7 && schSet.size<=10,'EXPECTED_SCHEMA_DDL_COUNT_UNEXPECTED');
 out('SCHEMA_SQL_BYTES_APPROX='+Buffer.byteLength(sql,'utf8'));
 out('CREATE_EXTENSION_NAMES='+[...extSet].sort().join(','));
 out('CREATE_SCHEMA_NAMES='+[...schSet].sort().join(','));
 out('CREATE_EXTENSION_STATEMENTS='+ext.length);
 out('CREATE_SCHEMA_STATEMENTS='+schemas.length);
 out('HAS_PG_CRON_EXTENSION_DDL='+(extSet.has('pg_cron')?'YES':'NO'));
 out('HAS_PG_NET_EXTENSION_DDL='+(extSet.has('pg_net')?'YES':'NO'));
 out('HAS_PG_STAT_STATEMENTS_EXTENSION_DDL='+(extSet.has('pg_stat_statements')?'YES':'NO'));
 out('[AVISO] CRON_AND_NET_EXTENSION_REQUIRE_PRELOAD_AWARE_RESTORE');
 out('[APROVADO] SQL_SCHEMA_DRYRUN_READ_ONLY_COMPLETED');
 out('[LIMITE] SQL generated in memory, never executed; no full restore attempted');
 out('[NEXT] CHOOSE_PRELOAD_SAFE_RESTORE_STRATEGY');
}
async function main(){
 const file=process.argv[2];
 req(file&&fs.existsSync(file)&&fs.statSync(file).isFile(),'BACKUP_NOT_FOUND');
 req(file.split(/[\\/]/).at(-1)===FILENAME,'BACKUP_FILENAME_MISMATCH');
 req(fs.statSync(file).size===SIZE,'BACKUP_SIZE_MISMATCH');
 const h=crypto.createHash('sha256');
 for await (const chunk of fs.createReadStream(file))h.update(chunk);
 req(h.digest('hex').toUpperCase()===SHA,'BACKUP_SHA256_MISMATCH');
 out('[OK] ENCRYPTED_BACKUP_SHA256_VERIFIED');
 checkDocker();
 const pass=await choosePassword();
 req(pass.length>0,'EMPTY_PASSWORD');
 await decrypt(file,pass,new Writable({write(_b,_e,next){next()}}));
 out('[OK] AES256_GCM_FULL_AUTH_AND_PGDMP_VERIFIED');
 await inspectSchemaSql(file,pass);
}
try{await main();process.exitCode=0}catch(e){out('[BLOQUEADO] CODIGO='+safeCode(String(e?.message||'')));process.exitCode=1}finally{
 if(process.platform==='win32'){
  try{spawnSync('clip.exe',[],{input:reports.join('\r\n'),encoding:'utf8',windowsHide:true,timeout:5000})}catch{}
 }
 stdout.write('[INFO] RELATORIO_SEM_SENHA_COPIADO\n');
}

#!/usr/bin/env node
// ROTA62 CLEAN6 v0.7.7. Read-only PostgreSQL custom dump TOC inspection.
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
const reports=['=== ROTA62 CLEAN6 BACKUP TOC PREFLIGHT v0.7.7 ===','[MODO] READ_ONLY_AUTHENTICATED_TOC_NO_RESTORE_NO_SQL'];
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
async function analyzeTOC(file,password){
 // pg_restore --list outputs only the archive catalog, with no SQL execution.
 const child=spawn('docker',['exec','-i','--user','postgres',SERVER,'pg_restore','--list'],{windowsHide:true,stdio:['pipe','pipe','pipe']});
 let text='',error='',overflow=false;
 child.stdout.on('data',b=>{if(text.length+b.length<4000000)text+=b.toString('utf8');else{overflow=true;child.kill()}});
 child.stderr.on('data',b=>{error=(error+b.toString('utf8')).slice(-1200)});
 const done=new Promise(resolve=>{
  child.once('error',e=>resolve({error:e}));
  child.once('close',(code,signal)=>resolve({code,signal}));
 });
 let streamError;
 try{await decrypt(file,password,child.stdin)}catch(e){streamError=e}
 if(streamError)child.kill();
 let timeout;
 const result=await Promise.race([done,new Promise(resolve=>{timeout=setTimeout(()=>{child.kill();resolve({timeout:true})},30000)})]);
 clearTimeout(timeout);
 req(!result.timeout,'PG_RESTORE_LIST_TIMEOUT');
 req(!overflow,'TOC_OUTPUT_TOO_LARGE');
 req(!result.error,'PG_RESTORE_CHILD_ERROR');
 // Decrypted stream already passed full authentication before streaming.
 // An early close here is not allowed for an audit intended to read the entire archive.
 req(!streamError,'TOC_PIPE_OR_CRYPTO_ERROR');
 req(result.code===0,'PG_RESTORE_LIST_FAILED');
 const entries=text.split(/\r?\n/).filter(x=>/^\s*\d+;\s+\d+\s+\d+\s+/.test(x));
 req(entries.length>100&&entries.length<10000,'TOC_ENTRY_COUNT_UNEXPECTED');
 const acl=entries.filter(x=>/^\s*\d+;\s+\d+\s+\d+\s+ACL\s/.test(x));
 const def=entries.filter(x=>/^\s*\d+;\s+\d+\s+\d+\s+DEFAULT ACL\s/.test(x));
 const ext=entries.filter(x=>/^\s*\d+;\s+\d+\s+\d+\s+EXTENSION\s/.test(x));
 const schemas=entries.filter(x=>/^\s*\d+;\s+\d+\s+\d+\s+SCHEMA\s/.test(x));
 const tables=entries.filter(x=>/^\s*\d+;\s+\d+\s+\d+\s+TABLE\s/.test(x));
 const tabledata=entries.filter(x=>/^\s*\d+;\s+\d+\s+\d+\s+TABLE DATA\s/.test(x));
 const owners=new Set();
 for(const x of entries){
  const bits=x.trim().split(/\s+/);
  const owner=bits.at(-1);
  if(owner&&/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(owner)&&owner!=='-')owners.add(owner);
 }
 out('TOC_TOTAL_ENTRIES='+entries.length);
 out('TOC_TABLE_OBJECTS='+tables.length);
 out('TOC_TABLE_DATA_OBJECTS='+tabledata.length);
 out('TOC_SCHEMA_OBJECTS='+schemas.length);
 out('TOC_EXTENSION_OBJECTS='+ext.length);
 out('TOC_ACL_OBJECTS='+acl.length);
 out('TOC_DEFAULT_ACL_OBJECTS='+def.length);
 out('TOC_DISTINCT_OWNER_TOKENS_APPROX='+owners.size);
 if(entries.length===919&&acl.length===210&&def.length===27){
  out('[OK] TOC_MATCHES_PRIOR_AUDIT_919_210_27');
 }else{out('[AVISO] TOC_COUNTS_DIFFER_FROM_PRIOR_AUDIT')}
 out('[APROVADO] AUTHENTICATED_PGDMP_TOC_READ_NO_DATABASE_CHANGES');
 out('[NEXT] DESIGN_SEPARATE_TEST_DB_ROLES_EXTENSIONS_RESTORE');
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
 await analyzeTOC(file,pass);
}
try{await main();process.exitCode=0}catch(e){out('[BLOQUEADO] CODIGO='+safeCode(String(e?.message||'')));process.exitCode=1}finally{
 if(process.platform==='win32'){
  try{spawnSync('clip.exe',[],{input:reports.join('\r\n'),encoding:'utf8',windowsHide:true,timeout:5000})}catch{}
 }
 stdout.write('[INFO] RELATORIO_SEM_SENHA_COPIADO\n');
}

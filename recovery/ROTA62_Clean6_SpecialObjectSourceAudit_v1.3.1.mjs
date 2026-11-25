#!/usr/bin/env node
// ROTA62 CLEAN6 v1.3.1. Read-only PostgreSQL custom dump TOC inspection.
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
const SERVER='rota62_guardian_clean6_restore_pg';
const reports=['=== ROTA62 CLEAN6 SPECIAL OBJECT SOURCE DEFINITION AUDIT v1.3.1 ===','[MODO] READ_ONLY_INSPECT_EVENT_TRIGGERS_PUBLICATIONS'];
function out(s){reports.push(s);stdout.write(s+'\n')}
function req(x,s){if(!x)throw Error(s)}
function safeCode(s){return /^[A-Z0-9_]{3,100}$/.test(s)?s:'LOCAL_ERROR_REDACTED'}
function docker(args){
 const p=spawnSync('docker',args,{encoding:'utf8',windowsHide:true,timeout:20000,maxBuffer:1024*1024});
 req(!p.error&&p.status===0,'DOCKER_READ_FAILED');return p.stdout.trim();
}
function dockerJSON(args){return JSON.parse(docker(args))}
function querySQL(db,statement){
 const p=spawnSync('docker',['exec','--user','postgres',SERVER,'psql','-X','-A','-t','-q',
 '-v','ON_ERROR_STOP=1','-h','/tmp','-U','postgres','-d',db,'-c',statement],
 {encoding:'utf8',windowsHide:true,timeout:20000,maxBuffer:10000});
 req(!p.error&&p.status===0,'PG_READ_ONLY_QUERY_FAILED');
 return p.stdout.trim();
}
function checkDocker(){
 const s=dockerJSON(['inspect',SERVER])[0];
 const direct=dockerJSON(['inspect','rota62_guardian_clean6_direct_pg'])[0];
 const init=dockerJSON(['inspect','rota62_guardian_clean6_pg'])[0];
 const ref=dockerJSON(['inspect','supabase_db_ROTA62_TESTE_SUPABASE'])[0];
 req(s?.Name==='/'+SERVER&&s?.State?.Running===true,'RESTORE_SERVER_NOT_RUNNING');
 req(direct?.State?.Running===false&&init?.State?.Running===false,'SECOND_CLEAN6_SERVER_RUNNING');
 req(ref?.State?.Running===true,'REFERENCE_STATE_CHANGED');
 req(/^sha256:[a-f0-9]{64}$/.test(s.Image)&&s.Image===direct.Image&&s.Image===init.Image&&s.Image===ref.Image,'SERVER_IMAGE_MISMATCH');
 req(s.HostConfig?.NetworkMode==='none'&&s.HostConfig?.RestartPolicy?.Name==='no'&&s.Config?.User==='postgres','ISOLATION_SETTINGS_MISMATCH');
 req(s.HostConfig?.ReadonlyRootfs===true&&s.HostConfig?.Privileged===false,'SERVER_PRIVILEGES_MISMATCH');
 req(s.HostConfig?.SecurityOpt?.includes('no-new-privileges')&&s.HostConfig?.CapDrop?.includes('ALL'),'SECURITY_OPTIONS_MISMATCH');
 req(s.Mounts?.length===1&&s.Mounts[0]?.Type==='volume'&&s.Mounts[0]?.Name==='rota62_guardian_clean6_data'&&s.Mounts[0]?.Destination==='/var/lib/postgresql/data','VOLUME_MISMATCH');
 req(Object.keys(s.HostConfig?.PortBindings||{}).length===0,'PORTS_PUBLISHED');
 const consumers=docker(['ps','--filter','volume=rota62_guardian_clean6_data','--format','{{.Names}}']).split(/\r?\n/).filter(Boolean);
 req(consumers.length===1&&consumers[0]===SERVER,'VOLUME_NOT_EXCLUSIVELY_OWNED');
 const cmd=['-D','/var/lib/postgresql/data','-c','listen_addresses=','-c','unix_socket_directories=/tmp',
 '-c','shared_preload_libraries=pg_cron,pg_net,pg_stat_statements','-c','max_worker_processes=4',
 '-c','cron.database_name=rota62_clean6_restore_v1','-c','cron.launch_active_jobs=off'];
 req(JSON.stringify(s.Config.Cmd)===JSON.stringify(cmd),'PRELOAD_SERVER_COMMAND_CHANGED');
 const ver=docker(['exec','--user','postgres',SERVER,'pg_restore','--version']);
 req(/PostgreSQL\)\s+17\./.test(ver),'PG_RESTORE_17_MISSING');
 const settings="SELECT CASE WHEN current_setting('server_version_num')::integer BETWEEN 170000 AND 179999 AND current_setting('listen_addresses')='' AND current_setting('unix_socket_directories')='/tmp' AND replace(current_setting('shared_preload_libraries'),' ','')='pg_cron,pg_net,pg_stat_statements' AND current_setting('cron.database_name')='rota62_clean6_restore_v1' AND current_setting('cron.launch_active_jobs')='off' THEN 'SAFE' ELSE 'UNSAFE' END";
 req(querySQL('postgres',settings)==='SAFE','RUNTIME_SETTINGS_UNSAFE');
 const dbs="SELECT CASE WHEN EXISTS(SELECT 1 FROM pg_database WHERE datname='rota62_clean6_restore_v1' AND pg_get_userbyid(datdba)='postgres') AND (SELECT count(*) FROM pg_database WHERE datname NOT IN ('template0','template1','postgres','rota62_clean6_restore_v1'))=0 THEN 'SAFE' ELSE 'UNSAFE' END";
 req(querySQL('postgres',dbs)==='SAFE','DATABASES_UNEXPECTED');
 const restored="SELECT (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p'))::text||'|'||(SELECT count(*) FROM pg_extension WHERE extname IN ('pg_cron','pg_net','pg_stat_statements','pgcrypto','supabase_vault','uuid-ossp'))::text";
 req(querySQL('rota62_clean6_restore_v1',restored)==='76|6','RESTORED_DB_STATE_UNEXPECTED');
 const roles="SELECT CASE WHEN count(*)=5 THEN 'SAFE' ELSE 'UNSAFE' END FROM pg_roles WHERE rolname IN ('pgbouncer','supabase_admin','supabase_auth_admin','supabase_realtime_admin','supabase_storage_admin') AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication";
 req(querySQL('postgres',roles)==='SAFE','NOLOGIN_SERVICE_ROLES_MISSING');
 out('[OK] CLEAN6_PRELOAD_SERVER_ONLY_VOLUME_CONSUMER');
 out('[OK] PG17_PRELOAD_CRON_JOBS_OFF_NO_TCP');
 out('[OK] RESTORED_DATABASE_76_TABLES_6_EXTENSIONS_FIVE_ROLES');
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
async function authenticateToMemory(file,password){
 const a=parseHeader(file);
 const key=crypto.scryptSync(password,Buffer.from(a.h.salt,'hex'),32,{N:32768,r:8,p:1,maxmem:128*1024*1024});
 const dec=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(a.h.nonce,'hex'));
 key.fill(0);
 dec.setAAD(a.preamble);dec.setAuthTag(a.tag);
 const cipher=await fs.promises.readFile(file);
 const plain=Buffer.concat([dec.update(cipher.subarray(a.start,a.end+1)),dec.final()]);
 req(plain.length===PLAIN&&plain.subarray(0,5).equals(Buffer.from('PGDMP','ascii')),'PGDMP_PAYLOAD_INVALID');
 return plain;
}
async function auditArchive(plain){
 const child=spawn('docker',['exec','-i','--user','postgres',SERVER,'pg_restore','--schema-only','--file=-'],{windowsHide:true,stdio:['pipe','pipe','pipe']});
 let sql='',tooLarge=false;
 child.stdout.on('data',buf=>{if(sql.length+buf.length<32000000)sql+=buf.toString('utf8');else{tooLarge=true;child.kill()}});
 child.stderr.on('data',()=>{});
 child.stdin.on('error',()=>{});
 const done=new Promise(resolve=>{child.once('error',()=>resolve({code:-1}));child.once('close',(code,signal)=>resolve({code,signal}))});
 child.stdin.end(plain);
 let timer;
 const state=await Promise.race([done,new Promise(resolve=>{timer=setTimeout(()=>{child.kill();resolve({timeout:true})},90000)})]);
 clearTimeout(timer);
 req(!state.timeout&&!tooLarge&&state.code===0&&sql.includes('PostgreSQL database dump'),'SCHEMA_SQL_GENERATION_FAILED');
 out('[OK] SOURCE_SCHEMA_SQL_AUTHENTICATED_IN_MEMORY_ONLY');
 const lines=sql.split(/\r?\n/);
 const createET=lines.filter(x=>/^CREATE\s+EVENT\s+TRIGGER\s+/i.test(x));
 const createPub=lines.filter(x=>/^CREATE\s+PUBLICATION\s+/i.test(x));
 const alterET=lines.filter(x=>/^ALTER\s+EVENT\s+TRIGGER\s+.*\bOWNER\s+TO\b/i.test(x));
 const alterPub=lines.filter(x=>/^ALTER\s+PUBLICATION\s+.*\bOWNER\s+TO\b/i.test(x));
 const otherET=lines.filter(x=>/^(?:ALTER|DROP|COMMENT\s+ON)\s+EVENT\s+TRIGGER\s+/i.test(x));
 const otherPub=lines.filter(x=>/^(?:ALTER|DROP|COMMENT\s+ON)\s+PUBLICATION\s+/i.test(x));
 out('SOURCE_CREATE_EVENT_TRIGGERS='+createET.length);
 out('SOURCE_CREATE_PUBLICATIONS='+createPub.length);
 out('SOURCE_ALTER_EVENT_TRIGGER_OWNER='+alterET.length);
 out('SOURCE_ALTER_PUBLICATION_OWNER='+alterPub.length);
 out('SOURCE_OTHER_EVENT_TRIGGER_LINES='+otherET.length);
 out('SOURCE_OTHER_PUBLICATION_LINES='+otherPub.length);
 const getName=(line,prefix)=>{const match=line.match(new RegExp('^'+prefix+'\\s+("(?:[^"]|"")*"|[A-Za-z_][A-Za-z_0-9]*)','i'));return match?match[1].replace(/^"|"$/g,''):'UNKNOWN'};
 const groups=new Map();
 for(const line of createET){const name=getName(line,'CREATE\\s+EVENT\\s+TRIGGER');groups.set('EVENT_TRIGGER|'+name, (groups.get('EVENT_TRIGGER|'+name)||0)+1)}
 for(const line of createPub){const name=getName(line,'CREATE\\s+PUBLICATION');groups.set('PUBLICATION|'+name, (groups.get('PUBLICATION|'+name)||0)+1)}
 for(const [key,num] of [...groups].sort((a,b)=>a[0].localeCompare(b[0])))out('SOURCE_SPECIAL_OBJECT='+key+' CREATE_LINES='+num);
 const owners=new Map();
 for(const [kind,list,prefix] of [['EVENT_TRIGGER',alterET,'ALTER\\s+EVENT\\s+TRIGGER'],['PUBLICATION',alterPub,'ALTER\\s+PUBLICATION']]){
  for(const line of list){
   const name=getName(line,prefix);
   const role=(line.match(/\bOWNER\s+TO\s+("(?:[^"]|"")*"|[a-z_][a-z_0-9]*)\s*;/i)||[])[1]||'UNKNOWN';
   const key=kind+'|'+name+'|OWNER='+role;
   owners.set(key,(owners.get(key)||0)+1);
  }
 }
 for(const [key,num] of [...owners].sort((a,b)=>a[0].localeCompare(b[0])))out('SOURCE_SPECIAL_OWNER='+key+' COUNT='+num);
 const sourceOk=createET.length===6&&createPub.length===2&&alterET.length===6&&alterPub.length===2;
 out('SOURCE_CREATE_OWNER_COVERAGE='+(sourceOk?'COMPLETE_6_2':'REQUIRES_REVIEW'));
 const existing=querySQL('rota62_clean6_restore_v1',"SELECT (SELECT count(*) FROM pg_event_trigger)::text||'|'||(SELECT count(*) FROM pg_publication)::text||'|'||(SELECT count(*) FROM pg_default_acl)::text");
 out('CLEAN6_SPECIAL_OBJECT_COUNTS='+existing);
 req(existing==='0|0|0','CLEAN6_SPECIAL_OBJECT_STATE_CHANGED');
 out('[OK] CLEAN6_UNCHANGED_SPECIAL_OBJECTS_ABSENT');
 out('[LIMITE] CREATE_STATEMENT_COUNTS_NOT_DDL_DEPENDENCY_OR_RUNTIME_VALIDATION');
 out('[LIMITE] EVENT_TRIGGERS_CAN_ACTIVATE_ON_DDL_AND_PUBLICATIONS_REQUIRE_REPLICATION_REVIEW');
 out('[LIMITE] NO_SQL_EXECUTED_FROM_SOURCE');
 if(sourceOk)out('[APROVADO] SPECIAL_OBJECT_SOURCE_INVENTORY_COMPLETE');
 else out('[PENDENTE] SOURCE_DDL_CLASSIFICATION_REQUIRES_REVIEW');
 out('[NEXT] REVIEW_SAFE_RECOVERY_ORDER_AND_TRIGGER_ACTIVATION');
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
 out('[INFO] PASSWORD_ENTRY_BEGIN');
 let pass=await choosePassword();
 req(pass.length>0,'EMPTY_PASSWORD');
 out('[OK] LOCAL_PASSWORD_INPUT_RECEIVED_NO_ECHO');
 const plain=await authenticateToMemory(file,pass);
 pass='';
 out('[OK] AES256_GCM_FULL_AUTH_AND_PGDMP_VERIFIED');
 out('[INFO] STARTING_SPECIAL_OBJECT_SOURCE_INSPECTION');
 try{await auditArchive(plain)}finally{plain.fill(0)}
}
try{await main();process.exitCode=0}catch(e){out('[BLOQUEADO] CODIGO='+safeCode(String(e?.message||'')));process.exitCode=1}finally{
 if(process.platform==='win32'){
  try{spawnSync('clip.exe',[],{input:reports.join('\r\n'),encoding:'utf8',windowsHide:true,timeout:5000})}catch{}
 }
 stdout.write('[INFO] RELATORIO_SEM_SENHA_COPIADO\n');
}

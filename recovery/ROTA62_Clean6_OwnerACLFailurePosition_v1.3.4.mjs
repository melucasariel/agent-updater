#!/usr/bin/env node
// ROTA62 CLEAN6 v1.3.4. Read-only PostgreSQL custom dump TOC inspection.
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
const reports=['=== ROTA62 CLEAN6 OWNER ACL FAILURE POSITION AUDIT v1.3.4 ===','[MODO] GUARDED_FIRST_FAILURE_MARKER_FORCE_ROLLBACK'];
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
function metadataFingerprint(){
 const q="SELECT md5("+
 "(SELECT coalesce(string_agg(c.oid::text||'='||pg_get_userbyid(c.relowner)||'='||coalesce(c.relacl::text,'NULL'),'|' ORDER BY c.oid),'') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')||'@'||"+
 "(SELECT coalesce(string_agg(p.oid::text||'='||pg_get_userbyid(p.proowner)||'='||coalesce(p.proacl::text,'NULL'),'|' ORDER BY p.oid),'') FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')||'@'||"+
 "(SELECT coalesce(string_agg(t.oid::text||'='||pg_get_userbyid(t.typowner)||'='||coalesce(t.typacl::text,'NULL'),'|' ORDER BY t.oid),'') FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')||'@'||"+
 "(SELECT coalesce(string_agg(n.oid::text||'='||pg_get_userbyid(n.nspowner)||'='||coalesce(n.nspacl::text,'NULL'),'|' ORDER BY n.oid),'') FROM pg_namespace n WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%')||'@'||"+
 "(SELECT coalesce(string_agg(d.oid::text||'='||d.defaclrole::text||'='||d.defaclnamespace::text||'='||d.defaclobjtype::text||'='||d.defaclacl::text,'|' ORDER BY d.oid),'') FROM pg_default_acl d)||'@'||"+
 "(SELECT coalesce(string_agg(e.oid::text||'='||e.evtname||'='||pg_get_userbyid(e.evtowner)||'='||e.evtenabled::text,'|' ORDER BY e.oid),'') FROM pg_event_trigger e)||'@'||"+
 "(SELECT coalesce(string_agg(p.oid::text||'='||p.pubname||'='||pg_get_userbyid(p.pubowner)||'='||p.puballtables::text||'='||p.pubinsert::text||'='||p.pubupdate::text||'='||p.pubdelete::text||'='||p.pubtruncate::text,'|' ORDER BY p.oid),'') FROM pg_publication p))";
 const x=querySQL('rota62_clean6_restore_v1',q);
 req(/^[0-9a-f]{32}$/.test(x),'METADATA_FINGERPRINT_INVALID');
 return x;
}
async function auditArchive(plain){
 const child=spawn('docker',['exec','-i','--user','postgres',SERVER,'pg_restore','--schema-only','--file=-'],{windowsHide:true,stdio:['pipe','pipe','pipe']});
 let sql='',tooLarge=false;
 child.stdout.on('data',b=>{if(sql.length+b.length<32000000)sql+=b.toString('utf8');else{tooLarge=true;child.kill()}});
 child.stderr.on('data',()=>{});
 child.stdin.on('error',()=>{});
 const finished=new Promise(resolve=>{child.once('error',()=>resolve({code:-1}));child.once('close',(code,signal)=>resolve({code,signal}))});
 child.stdin.end(plain);
 let timer;
 const state=await Promise.race([finished,new Promise(resolve=>{timer=setTimeout(()=>{child.kill();resolve({timeout:true})},90000)})]);
 clearTimeout(timer);
 req(!state.timeout&&!tooLarge&&state.code===0&&sql.includes('PostgreSQL database dump'),'SOURCE_OWNER_ACL_SQL_GENERATION_FAILED');
 out('[OK] AUTHENTICATED_OWNER_ACL_SQL_EXTRACTED_IN_MEMORY');
 const lines=sql.split(/\r?\n/);
 const owner=lines.filter(l=>/^ALTER\s+.*\bOWNER\s+TO\b/i.test(l));
 const allowedOwner=/^ALTER\s+(?:MATERIALIZED VIEW|FOREIGN TABLE|EVENT TRIGGER|PUBLICATION|TABLE|SEQUENCE|FUNCTION|PROCEDURE|SCHEMA|TYPE|DOMAIN|VIEW|AGGREGATE)\s+.+\s+OWNER\s+TO\s+(?:"(?:[^"]|"")*"|[A-Za-z_][A-Za-z_0-9]*)\s*;\s*$/i;
 const acl=lines.filter(l=>/^(?:GRANT|REVOKE|ALTER DEFAULT PRIVILEGES)\b/i.test(l));
 const aclGrants=acl.filter(l=>/^(?:GRANT|REVOKE)\b/i.test(l));
 const aclDefaults=acl.filter(l=>/^ALTER DEFAULT PRIVILEGES\b/i.test(l));
 req(owner.length===191&&owner.every(l=>allowedOwner.test(l)),'OWNER_191_COVERAGE_FAILED');
 req(acl.length===595&&aclGrants.length===522&&aclDefaults.length===73,'ACL_595_COVERAGE_FAILED');
 req([...owner,...acl].every(l=>l.trim().endsWith(';')&&l.split(';').length===2),'SQL_STATEMENT_MULTILINE_OR_EXTRA_DELIMITER');
 out('SOURCE_OWNER_STATEMENTS='+owner.length);
 out('SOURCE_ACL_STATEMENTS='+acl.length);
 const baseline=querySQL('rota62_clean6_restore_v1',"SELECT (SELECT count(*) FROM pg_event_trigger)::text||'|'||(SELECT count(*) FROM pg_publication)::text||'|'||(SELECT count(*) FROM pg_default_acl)::text||'|'||(SELECT count(*) FROM pg_policy)::text||'|'||(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p'))::text");
 req(baseline==='6|2|0|10|76','SPECIAL_OBJECT_BASELINE_CHANGED');
 const events=querySQL('rota62_clean6_restore_v1',"SELECT count(*)::text FROM pg_event_trigger WHERE evtenabled='O' AND evtowner=(SELECT oid FROM pg_roles WHERE rolname='postgres')");
 req(events==='6','EVENT_TRIGGER_BASELINE_CHANGED');
 const ownerRoles=new Set([...owner].map(l=>(l.match(/\bOWNER\s+TO\s+("(?:[^"]|"")*"|[A-Za-z_][A-Za-z_0-9]*)\s*;\s*$/i)||[])[1]).filter(Boolean).map(x=>x.replace(/^"|"$/g,'')));
 const roles=new Set(querySQL('postgres',"SELECT rolname FROM pg_roles").split(/\r?\n/).filter(Boolean));
 req([...ownerRoles].every(x=>roles.has(x)),'OWNER_TARGET_ROLE_MISSING');
 const restricted=['anon','authenticated','dashboard_user','service_role','supabase_functions_admin'];
 req(querySQL('postgres',"SELECT count(*)::text FROM pg_roles WHERE rolname IN ("+restricted.map(x=>"'"+x+"'").join(',')+") AND NOT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls")==='5','REQUIRED_ROLES_UNSAFE');
 const before=metadataFingerprint();
 out('[OK] CLEAN6_METADATA_BASELINE_CAPTURED');
 const ownerTagged=owner.map((stmt,i)=>'\\echo R62_PHASE_OWNER_INDEX_'+String(i+1).padStart(3,'0')+'\\n'+stmt).join('\\n');
 const aclTagged=acl.map((stmt,i)=>'\\echo R62_PHASE_ACL_INDEX_'+String(i+1).padStart(3,'0')+'\\n'+stmt).join('\\n');
 const payload="\\echo R62_PHASE_BEGIN\\nBEGIN;\\n\\echo R62_PHASE_SET_REPLICA\\nSET LOCAL session_replication_role = 'replica';\\n\\echo R62_PHASE_SET_TIMEOUT\\nSET LOCAL statement_timeout = '60s';\\n"+ownerTagged+"\\nSELECT 'R62_OWNER_191_EXECUTED';\\n"+aclTagged+"\\nSELECT 'R62_ACL_595_EXECUTED';\\nROLLBACK;\\nSELECT 'R62_ALL_ROLLED_BACK';\\n";
 const test=spawn('docker',['exec','-i','--user','postgres',SERVER,'psql','-X','-A','-t','-v','ON_ERROR_STOP=1','-v','VERBOSITY=sqlstate','-v','SHOW_CONTEXT=never','-h','/tmp','-U','postgres','-d','rota62_clean6_restore_v1','-f','-'],{windowsHide:true,stdio:['pipe','pipe','pipe']});
 let stdoutText='',stderrText='',overflow=false;
 test.stdout.on('data',b=>{if(stdoutText.length+b.length<120000)stdoutText+=b.toString('utf8');else{overflow=true;test.kill()}});
 test.stderr.on('data',b=>{if(stderrText.length+b.length<120000)stderrText+=b.toString('utf8');else{overflow=true;test.kill()}});
 test.stdin.on('error',()=>{});
 const done=new Promise(resolve=>{test.once('error',()=>resolve({code:-1}));test.once('close',(code,signal)=>resolve({code,signal}))});
 test.stdin.end(payload,'utf8');
 let timer2;const result=await Promise.race([done,new Promise(resolve=>{timer2=setTimeout(()=>{test.kill();resolve({timeout:true})},120000)})]);
 clearTimeout(timer2);
 const phaseMarks=[...stdoutText.matchAll(/R62_PHASE_(?:BEGIN|SET_REPLICA|SET_TIMEOUT|OWNER_INDEX_[0-9]{3}|ACL_INDEX_[0-9]{3})/g)].map(m=>m[0]);
 const lastPhase=phaseMarks.at(-1)||'UNKNOWN';
 out('LAST_EXECUTED_PHASE_MARKER='+lastPhase);
 out('TOTAL_PHASE_MARKERS='+phaseMarks.length);
 const ownerPassed=stdoutText.includes('R62_OWNER_191_EXECUTED');
 const aclPassed=stdoutText.includes('R62_ACL_595_EXECUTED');
 const rolledBack=result.code===0&&ownerPassed&&aclPassed&&stdoutText.includes('R62_ALL_ROLLED_BACK');
 if(result.timeout)out('[BLOQUEADO] TRANSACTION_TIMEOUT_PROCESS_KILLED');
 if(overflow)out('[BLOQUEADO] TRANSACTION_OUTPUT_OVERFLOW_PROCESS_KILLED');
 out('OWNER_TEST_REACHED_END='+(ownerPassed?'YES':'NO'));
 out('ACL_TEST_REACHED_END='+(aclPassed?'YES':'NO'));
 out('EXPLICIT_ROLLBACK_CONFIRMED='+(rolledBack?'YES':'NO'));
 if(!rolledBack){
  const errCode=(stderrText.match(/\b(?:ERROR|FATAL):?\s+([0-9A-Z]{5})\b/i)||[])[1]||'UNKNOWN';
  out('[BLOQUEADO] OWNER_ACL_DRYRUN_SQLSTATE='+errCode);
  out('DRYRUN_EXIT_CODE='+String(result.code??-1));
  out('[INFO] SESSION_TERMINATION_ROLLBACK_EXPECTED');
 }
 const after=metadataFingerprint();
 const afterState=querySQL('rota62_clean6_restore_v1',"SELECT (SELECT count(*) FROM pg_event_trigger)::text||'|'||(SELECT count(*) FROM pg_publication)::text||'|'||(SELECT count(*) FROM pg_default_acl)::text||'|'||(SELECT count(*) FROM pg_policy)::text");
 const unchanged=before===after&&afterState==='6|2|0|10';
 out('OWNER_ACL_STATE_POSTCHECK='+(unchanged?'UNCHANGED':'CHANGED'));
 req(unchanged,'OWNER_ACL_STATE_CHANGED');
 if(!rolledBack){out('[NEXT] REVIEW_FIRST_SQLSTATE_BEFORE_RETRY');return}
 out('[OK] ALL_191_OWNER_AND_595_ACL_STATEMENTS_EXECUTED_WITH_FORCED_ROLLBACK');
 out('[APROVADO] CLEAN6_COMBINED_OWNER_ACL_DRY_RUN_COMPLETE');
 out('[NEXT] PLAN_CONTROLLED_COMMIT_ONLY_AFTER_OWNER_SEMANTICS_REVIEW');
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
 out('[INFO] STARTING_FIRST_FAILURE_PHASE_TRACE_FORCE_ROLLBACK');
 try{await auditArchive(plain)}finally{plain.fill(0)}
}
try{await main();process.exitCode=0}catch(e){out('[BLOQUEADO] CODIGO='+safeCode(String(e?.message||'')));process.exitCode=1}finally{
 if(process.platform==='win32'){
  try{spawnSync('clip.exe',[],{input:reports.join('\r\n'),encoding:'utf8',windowsHide:true,timeout:5000})}catch{}
 }
 stdout.write('[INFO] RELATORIO_SEM_SENHA_COPIADO\n');
}

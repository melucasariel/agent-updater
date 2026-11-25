#!/usr/bin/env node
// ROTA62 CLEAN6 v1.1.2. Read-only PostgreSQL custom dump TOC inspection.
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
const reports=['=== ROTA62 CLEAN6 ACL PARSER GAP AUDIT v1.1.2 ===','[MODO] READ_ONLY_DIAGNOSE_UNPARSED_ACL_STATEMENTS'];
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
 const args=['exec','-i','--user','postgres',SERVER,'pg_restore','--schema-only','--no-owner','--file=-'];
 const child=spawn('docker',args,{windowsHide:true,stdio:['pipe','pipe','pipe']});
 let sql='',stderr='',tooLarge=false,earlyClose=false;
 child.stdout.on('data',b=>{if(sql.length+b.length<32000000)sql+=b.toString('utf8');else{tooLarge=true;child.kill()}});
 child.stderr.on('data',b=>{stderr=(stderr+b.toString('utf8')).slice(-2000)});
 child.stdin.on('error',()=>{earlyClose=true});
 const done=new Promise(resolve=>{child.once('error',()=>resolve({code:-1}));child.once('close',(code,signal)=>resolve({code,signal}))});
 child.stdin.end(plain);
 let timer;
 const result=await Promise.race([done,new Promise(resolve=>{timer=setTimeout(()=>{child.kill();resolve({timeout:true})},90000)})]);
 clearTimeout(timer);
 req(!result.timeout,'ACL_SQL_TIMEOUT');
 req(!tooLarge,'ACL_SQL_TOO_LARGE');
 req(result.code===0,'ACL_SQL_GENERATION_FAILED');
 req(sql.length>3000&&sql.includes('PostgreSQL database dump'),'ACL_SQL_INVALID');
 out('[OK] ARCHIVE_SCHEMA_WITH_ACL_GENERATED_IN_MEMORY_ONLY');
 if(earlyClose)out('[INFO] EARLY_STDIN_CLOSE_AFTER_VALID_SQL');
 const lines=sql.split(/\r?\n/);
 const grantLines=lines.filter(x=>/^(?:GRANT|REVOKE)\s/i.test(x));
 const defaultLines=lines.filter(x=>/^ALTER DEFAULT PRIVILEGES\b/i.test(x));
 const ownerLines=lines.filter(x=>/^ALTER\s+[^;\n]+\s+OWNER\s+TO\b/i.test(x));
 out('ARCHIVE_GRANT_REVOKE_SQL_LINES='+grantLines.length);
 out('ARCHIVE_DEFAULT_PRIVILEGE_SQL_LINES='+defaultLines.length);
 out('ARCHIVE_OWNER_SQL_LINES='+ownerLines.length);

 const all=lines.filter(x=>/^(?:GRANT|REVOKE|ALTER DEFAULT PRIVILEGES)\b/i.test(x));
 const classify=(x)=>{if(/^ALTER DEFAULT PRIVILEGES/i.test(x))return 'DEFAULT_PRIVILEGES';
 if(/\bON\s+ALL\s+TABLES\s+IN\s+SCHEMA\b/i.test(x))return 'ALL_TABLES_IN_SCHEMA';
 if(/\bON\s+ALL\s+SEQUENCES\s+IN\s+SCHEMA\b/i.test(x))return 'ALL_SEQUENCES_IN_SCHEMA';
 if(/\bON\s+ALL\s+FUNCTIONS\s+IN\s+SCHEMA\b/i.test(x))return 'ALL_FUNCTIONS_IN_SCHEMA';
 if(/\bON\s+SCHEMA\b/i.test(x))return 'SCHEMA';
 if(/\bON\s+(?:TABLE|TABLES)\b/i.test(x))return 'TABLE';
 if(/\bON\s+SEQUENCE\b/i.test(x))return 'SEQUENCE';
 if(/\bON\s+(?:FUNCTION|PROCEDURE|ROUTINE)\b/i.test(x))return 'FUNCTION';
 if(/\bON\s+DATABASE\b/i.test(x))return 'DATABASE';
 if(/\bON\s+TYPE\b/i.test(x))return 'TYPE';
 if(/\bON\s+FOREIGN\b/i.test(x))return 'FOREIGN';
 if(/\bON\s+LANGUAGE\b/i.test(x))return 'LANGUAGE';
 if(/\bON\s+TABLESPACE\b/i.test(x))return 'TABLESPACE';
 return 'OTHER';};
 const buckets=new Map();
 for(const x of all){const key=(/^REVOKE\b/i.test(x)?'REVOKE':/^GRANT\b/i.test(x)?'GRANT':'ALTER_DEFAULT')+'_'+classify(x);buckets.set(key,(buckets.get(key)||0)+1)}
 for(const [key,count] of [...buckets].sort((a,b)=>a[0].localeCompare(b[0])))out('ACL_SQL_CLASS='+key+' COUNT='+count);
 out('ACL_SQL_CLASSIFIED='+all.length);
 const roleList=['postgres','supabase_admin','supabase_auth_admin','supabase_storage_admin','dashboard_user','anon','authenticated','service_role','supabase_functions_admin'];
 const roleData=querySQL('postgres',"SELECT rolname||'|'||CASE WHEN rolcanlogin THEN 'LOGIN' ELSE 'NOLOGIN' END||'|'||CASE WHEN rolsuper THEN 'SUPER' ELSE 'NOSUPER' END||'|'||CASE WHEN rolbypassrls THEN 'BYPASSRLS' ELSE 'NOBYPASSRLS' END FROM pg_roles WHERE rolname IN ("+roleList.map(x=>"'"+x+"'").join(',')+") ORDER BY rolname");
 for(const row of roleData.split(/\r?\n/).filter(Boolean))out('ACL_ROLE_CAPABILITY='+row);
 const defowners=new Map();
 for(const x of defaultLines){const m=x.match(/\bFOR\s+ROLE\s+((?:"[^"]+"|[a-z_][a-z0-9_]*)(?:\s*,\s*(?:"[^"]+"|[a-z_][a-z0-9_]*))*)\s+/i);if(m)for(const item of m[1].split(',')){const k=item.trim().replace(/^"|"$/g,'');defowners.set(k,(defowners.get(k)||0)+1)}}
 for(const [k,v] of [...defowners].sort((a,b)=>a[0].localeCompare(b[0])))out('DEFAULT_ACL_SOURCE_OWNER='+k+' SQL_LINES='+v);
 const state=querySQL('rota62_clean6_restore_v1',"SELECT count(*)::text||'|'||(SELECT count(*)::text FROM pg_policy)||'|'||(SELECT count(*)::text FROM pg_default_acl) FROM pg_extension WHERE extname IN ('pg_cron','pg_net','pg_stat_statements','pgcrypto','supabase_vault','uuid-ossp')");
 req(state==='6|10|0','RESTORE_STATE_CHANGED');
 out('[OK] CLEAN6_ACL_STATE_STILL_UNMODIFIED');


 const sourceCounts=new Map();
 const highPriv=new Map();
 let parsed=0,unparsed=0,multiRole=0;
 const targetClasses=['TABLE','FUNCTION','SCHEMA','SEQUENCE','DEFAULT_PRIVILEGES'];
 for(const statement of all){
  const isDefault=/^ALTER DEFAULT PRIVILEGES\b/i.test(statement);
  const m=statement.match(/\b(?:TO|FROM)\s+((?:"[^"]+"|[A-Za-z_][A-Za-z_0-9]*)(?:\s*,\s*(?:"[^"]+"|[A-Za-z_][A-Za-z_0-9]*))*)\s*;?\s*$/i);
  if(!m){unparsed++;continue}
  parsed++;
  const names=m[1].split(',').map(x=>x.trim().replace(/^"|"$/g,'').toLowerCase());
  if(names.length>1)multiRole++;
  const kind=classify(statement);
  const verb=isDefault?'DEFAULT':/^GRANT\b/i.test(statement)?'GRANT':'REVOKE';
  for(const role of names){
   if(!/^[a-z_][a-z0-9_]{0,62}$/.test(role))continue;
   const label=role+'|'+verb+'|'+kind;
   sourceCounts.set(label,(sourceCounts.get(label)||0)+1);
   if(/^(public|anon|authenticated)$/.test(role)&&verb==='GRANT'&&
     /^(TABLE|SEQUENCE|SCHEMA|FUNCTION)$/.test(kind)&&
     /\b(?:ALL|TRUNCATE|TRIGGER|REFERENCES|CREATE|DELETE|UPDATE|INSERT|EXECUTE)\b/i.test(statement)){
       const risk=role+'|'+kind;
       highPriv.set(risk,(highPriv.get(risk)||0)+1);
   }
  }
 }
 out('ACL_SOURCE_STATEMENTS_PARSED='+parsed);
 out('ACL_SOURCE_STATEMENTS_UNPARSED='+unparsed);

 const gaps=new Map(), unparsedCategories=new Map();
 const granteeSuffix=/\b(?:TO|FROM)\s+((?:"[^"]+"|[A-Za-z_][A-Za-z_0-9]*)(?:\s*,\s*(?:"[^"]+"|[A-Za-z_][A-Za-z_0-9]*))*)\s*;?\s*$/i;
 const incr=(map,key)=>map.set(key,(map.get(key)||0)+1);
 for(const statement of all){
  if(granteeSuffix.test(statement))continue;
  const verb=/^ALTER DEFAULT PRIVILEGES/i.test(statement)?'DEFAULT':/^GRANT\b/i.test(statement)?'GRANT':'REVOKE';
  incr(unparsedCategories,verb+'_'+classify(statement));
  const normalized=statement.replace(/;\s*$/,'').trim();
  let reason='UNCLASSIFIED';
  if(/\bWITH\s+GRANT\s+OPTION$/i.test(normalized))reason='WITH_GRANT_OPTION';
  else if(/\bGRANTED\s+BY\s+(?:"[^"]+"|[A-Za-z_][A-Za-z_0-9]*)$/i.test(normalized))reason='GRANTED_BY';
  else if(/\b(?:TO|FROM)\s+(?:GROUP\s+)?(?:PUBLIC|CURRENT_USER|SESSION_USER)\s*$/i.test(normalized))reason='ROLE_KEYWORD_OR_GROUP';
  else if(/\b(?:TO|FROM)\b/i.test(normalized))reason='TO_FROM_WITH_COMPLEX_TRAILING_SYNTAX';
  else reason='NO_TERMINAL_TO_FROM';
  incr(gaps,reason);
 }
 for(const [kind,count] of [...unparsedCategories].sort())out('UNPARSED_SQL_CLASS='+kind+' COUNT='+count);
 for(const [kind,count] of [...gaps].sort())out('UNPARSED_REASON='+kind+' COUNT='+count);
 req([...gaps.values()].reduce((a,b)=>a+b,0)===unparsed,'UNPARSED_CLASSIFICATION_COUNT_MISMATCH');
 out('[LIMITE] UNPARSED_DIAGNOSIS_COUNTS_ONLY_SQL_NOT_EXPOSED');

 out('ACL_SOURCE_MULTI_GRANTEE_STATEMENTS='+multiRole);
 for(const role of ['public','anon','authenticated','service_role','dashboard_user','supabase_admin','supabase_auth_admin','supabase_storage_admin','supabase_functions_admin','pgbouncer','supabase_realtime_admin','postgres']){
  let grant=0,revoke=0,def=0;
  for(const [label,count] of sourceCounts){const [name,verb]=label.split('|');if(name!==role)continue;if(verb==='GRANT')grant+=count;else if(verb==='REVOKE')revoke+=count;else def+=count}
  if(grant||revoke||def)out('SOURCE_ACL_GRANTEE='+role+' GRANT='+grant+' REVOKE='+revoke+' DEFAULT='+def);
 }
 for(const [roleKind,count] of [...highPriv.entries()].sort())out('SOURCE_SENSITIVE_GRANT_CATEGORY='+roleKind+' STATEMENTS='+count);
 out('[LIMITE] GRANTEE_PRIVILEGE_CLASSIFICATION_IS_HEURISTIC_NOT_EXACT_SEMANTICS');
 const roleSet=new Map();
 const add=(name,category)=>{
  name=name.trim().replace(/^"|"$/g,'').toLowerCase();
  if(!/^[a-z_][a-z0-9_]{0,62}$/.test(name))return;
  if(!roleSet.has(name))roleSet.set(name,new Set());
  roleSet.get(name).add(category);
 };
 for(const x of grantLines){
  const m=x.match(/\b(?:TO|FROM)\s+((?:"[^"]+"|[A-Za-z_][A-Za-z_0-9]*)(?:\s*,\s*(?:"[^"]+"|[A-Za-z_][A-Za-z_0-9]*))*)\s*;?\s*$/i);
  if(m)for(const v of m[1].split(','))add(v,'EXPLICIT_GRANT');
 }
 for(const x of defaultLines){
  const m=x.match(/\bFOR\s+ROLE\s+((?:"[^"]+"|[A-Za-z_][A-Za-z_0-9]*)(?:\s*,\s*(?:"[^"]+"|[A-Za-z_][A-Za-z_0-9]*))*)\s+(?:IN\s+SCHEMA|GRANT|REVOKE)\b/i);
  if(m)for(const v of m[1].split(','))add(v,'DEFAULT_PRIVILEGE_OWNER');
  const dest=x.match(/\b(?:TO|FROM)\s+((?:"[^"]+"|[A-Za-z_][A-Za-z_0-9]*)(?:\s*,\s*(?:"[^"]+"|[A-Za-z_][A-Za-z_0-9]*))*)\s*;?\s*$/i);
  if(dest)for(const v of dest[1].split(','))add(v,'DEFAULT_PRIVILEGE_GRANTEE');
 }
 const existing=new Set(querySQL('postgres','SELECT rolname FROM pg_roles ORDER BY rolname').split(/\r?\n/).filter(Boolean));
 for(const [name,kinds] of [...roleSet.entries()].sort((a,b)=>a[0].localeCompare(b[0]))){
  out('ACL_ROLE='+name+' STATUS='+(name==='public'||existing.has(name)?'PRESENT':'MISSING')+' CONTEXT='+[...kinds].sort().join('+'));
 }
 out('ACL_ROLE_REFERENCES='+roleSet.size);
 out('ACL_ROLE_MISSING='+[...roleSet.keys()].filter(x=>x!=='public'&&!existing.has(x)).length);
 const def=querySQL('rota62_clean6_restore_v1',"SELECT count(*)::text FROM pg_default_acl");
 out('CURRENT_DEFAULT_ACL_ENTRIES='+def);
 out('[LIMITE] SQL_LINE_PARSER_COUNTS_NOT_FULL_SEMANTIC_ACL_COMPARISON');
 out('[LIMITE] NO_ACL_SQL_WAS_EXECUTED');
 out('[APROVADO] CLEAN6_ACL_REPLAY_READINESS_AUDIT_COMPLETE');
 out('[NEXT] REVIEW_ROLE_DEPENDENCIES_AND_PLAN_CONTROLLED_ACL_RECOVERY');
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
 out('[INFO] STARTING_ARCHIVE_ACL_SQL_INSPECTION');
 try{await auditArchive(plain)}finally{plain.fill(0)}
}
try{await main();process.exitCode=0}catch(e){out('[BLOQUEADO] CODIGO='+safeCode(String(e?.message||'')));process.exitCode=1}finally{
 if(process.platform==='win32'){
  try{spawnSync('clip.exe',[],{input:reports.join('\r\n'),encoding:'utf8',windowsHide:true,timeout:5000})}catch{}
 }
 stdout.write('[INFO] RELATORIO_SEM_SENHA_COPIADO\n');
}

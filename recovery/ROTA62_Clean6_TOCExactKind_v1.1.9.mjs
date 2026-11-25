#!/usr/bin/env node
// ROTA62 CLEAN6 v1.1.9. Read-only PostgreSQL custom dump TOC inspection.
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
const reports=['=== ROTA62 CLEAN6 TOC EXACT KIND CLASSIFICATION AUDIT v1.1.9 ===','[MODO] READ_ONLY_SEPARATE_COMPOUND_TOC_ENTRY_KINDS'];
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
 const child=spawn('docker',['exec','-i','--user','postgres',SERVER,'pg_restore','--list'],{windowsHide:true,stdio:['pipe','pipe','pipe']});
 let toc='',tooLarge=false;
 child.stdout.on('data',d=>{if(toc.length+d.length<2000000)toc+=d.toString('utf8');else{tooLarge=true;child.kill()}});
 child.stderr.on('data',()=>{});
 child.stdin.on('error',()=>{});
 const done=new Promise(resolve=>{child.once('error',()=>resolve({code:-1}));child.once('close',(code,signal)=>resolve({code,signal}))});
 child.stdin.end(plain);
 let timer;
 const status=await Promise.race([done,new Promise(resolve=>{timer=setTimeout(()=>{child.kill();resolve({timeout:true})},60000)})]);
 clearTimeout(timer);
 req(!status.timeout&&!tooLarge&&status.code===0&&toc.includes('TOC Entries'),'TOC_READ_FAILED');
 const lines=toc.split(/\r?\n/).filter(x=>/^\d+;\s+\d+\s+\d+\s/.test(x));
 req(lines.length===919,'ARCHIVE_TOC_COUNT_CHANGED');
 out('[OK] ORIGINAL_TOC_919_ENTRIES_READONLY');

 const relevant=['TABLE DATA','TABLE ATTACH','TABLE','SEQUENCE SET','SEQUENCE OWNED BY','SEQUENCE','SCHEMA'];
 const counts=new Map(), malformed=new Map(), ambiguous=new Map();
 for(const line of lines){
  const m=line.match(/^\d+;\s+\d+\s+\d+\s+(.+)$/);if(!m)continue;
  const desc=m[1],kind=relevant.find(t=>desc.startsWith(t+' '));
  if(!kind)continue;
  counts.set(kind,(counts.get(kind)||0)+1);
  if(!['TABLE','SEQUENCE','SCHEMA'].includes(kind))continue;
  const rest=desc.slice(kind.length).trim(), tokens=rest.split(/\s+/);
  if(tokens.length!==3){
    const group=kind+'|TOKENS_'+tokens.length+(tokens.includes('-')?'|HAS_HYPHEN':'');
    malformed.set(group,(malformed.get(group)||0)+1);
    if(tokens.length>=3){
      const schema=tokens[0],owner=tokens.at(-1);
      const candidate=tokens.slice(1,-1).join(' ');
      const shape=kind+'|NAME_WORDS_'+(tokens.length-2)+'|SCHEMA_'+(/^[a-z_]+$/.test(schema)?schema:'COMPLEX')+'|OWNER_'+(/^[a-z_]+$/.test(owner)?owner:'COMPLEX');
      ambiguous.set(shape,(ambiguous.get(shape)||0)+1);
      req(candidate.length>0,'EMPTY_NAME_IN_TOC');
    }
  }
 }
 for(const kind of relevant)out('EXACT_TOC_KIND='+kind+' COUNT='+(counts.get(kind)||0));
 for(const [key,count] of [...malformed].sort())out('TOC_NAME_TOKEN_SHAPE='+key+' COUNT='+count);
 for(const [key,count] of [...ambiguous].sort())out('TOC_NAME_STRUCTURE='+key+' COUNT='+count);
 out('[LIMITE] NO_OBJECT_IDENTIFIERS_EXPOSED_IN_COMPOUND_KIND_DIAGNOSTIC');
 const source=new Map(), sourceTypes=new Map(), sourceOwnerCounts=new Map();
 for(const line of lines){
  const m=line.match(/^\d+;\s+\d+\s+\d+\s+(TABLE|SEQUENCE|SCHEMA)\s+(\S+)\s+(\S+)\s+(\S+)\s*$/);
  if(!m)continue;
  const [,type,schema,name,owner]=m;
  const key=type+'|'+(type==='SCHEMA'?name:schema+'.'+name);
  sourceTypes.set(type,(sourceTypes.get(type)||0)+1);
  if(source.has(key))req(false,'SOURCE_OBJECT_DUPLICATE');
  source.set(key,owner);
  sourceOwnerCounts.set(type+'|'+owner,(sourceOwnerCounts.get(type+'|'+owner)||0)+1);
 }
 const query="SELECT 'TABLE|'||n.nspname||'.'||c.relname||'|'||pg_get_userbyid(c.relowner) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p') "+
 "UNION ALL SELECT 'SEQUENCE|'||n.nspname||'.'||c.relname||'|'||pg_get_userbyid(c.relowner) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind='S' "+
 "UNION ALL SELECT 'SCHEMA|'||n.nspname||'|'||pg_get_userbyid(n.nspowner) FROM pg_namespace n WHERE n.nspname IN ('auth','extensions','graphql','graphql_public','pgbouncer','realtime','storage','vault') ORDER BY 1";
 const current=new Map(), currentTypeCounts=new Map();
 for(const line of querySQL('rota62_clean6_restore_v1',query).split(/\r?\n/).filter(Boolean)){
  const p=line.split('|');req(p.length===3,'CURRENT_IDENTITY_DELIMITER_UNEXPECTED');
  const key=p[0]+'|'+p[1];req(!current.has(key),'CURRENT_DUPLICATE_OBJECT_IDENTITY');
  current.set(key,p[2]);currentTypeCounts.set(p[0],(currentTypeCounts.get(p[0])||0)+1);
 }
 let matches=0,mismatches=0,missing=0,extra=0;
 const differing=new Map(), missingList=[],extraList=[];
 for(const [key,owner] of source){
  const type=key.split('|')[0];
  if(!current.has(key)){missing++;missingList.push(type+'|'+key.slice(type.length+1));continue}
  const actual=current.get(key);
  if(actual===owner)matches++;
  else{mismatches++;const group=type+'|'+owner+'|'+actual;differing.set(group,(differing.get(group)||0)+1)}
 }
 for(const key of current.keys())if(!source.has(key)){extra++;const type=key.split('|')[0];extraList.push(type+'|'+key.slice(type.length+1))}
 for(const type of ['TABLE','SEQUENCE','SCHEMA']){
  out('SOURCE_OBJECT_COUNT_'+type+'='+(sourceTypes.get(type)||0));
  out('CURRENT_OBJECT_COUNT_'+type+'='+(currentTypeCounts.get(type)||0));
 }
 out('OBJECT_OWNER_MATCH='+matches);
 out('OBJECT_OWNER_MISMATCH='+mismatches);
 out('OBJECT_ABSENT_FROM_CLEAN6='+missing);
 out('OBJECT_EXTRA_IN_CLEAN6='+extra);
 for(const [name,count] of [...differing].sort((a,b)=>a[0].localeCompare(b[0])))out('OWNER_MISMATCH_GROUP='+name+' COUNT='+count);
 for(const obj of missingList.slice(0,15))out('SOURCE_ONLY_OBJECT='+obj);
 for(const obj of extraList.slice(0,15))out('TARGET_ONLY_OBJECT='+obj);
 if(missingList.length>15||extraList.length>15)out('[LIMITE] OBJECT_NAME_SAMPLE_CAPPED_AT_15_EACH');
 const total=matches+mismatches+missing;
 req(total===source.size,'SOURCE_RECONCILIATION_COUNT_MISMATCH');
 out('[LIMITE] FUNCTION_AND_TYPE_OBJECTS_NOT_COMPARED_IN_THIS_STEP');
 out('[LIMITE] OWNER_SOURCE_TOC_NAMES_PARSER_REQUIRES_REVIEW_FOR_SPECIAL_IDENTIFIER_NAMES');
 out('[APROVADO] CLEAN6_TOC_EXACT_KIND_CLASSIFICATION_COMPLETE');
 out('[NEXT] REVIEW_MISSING_EXTRA_AND_OWNER_GROUPS');
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
 out('[INFO] STARTING_OBJECT_OWNER_NAME_COMPARISON');
 try{await auditArchive(plain)}finally{plain.fill(0)}
}
try{await main();process.exitCode=0}catch(e){out('[BLOQUEADO] CODIGO='+safeCode(String(e?.message||'')));process.exitCode=1}finally{
 if(process.platform==='win32'){
  try{spawnSync('clip.exe',[],{input:reports.join('\r\n'),encoding:'utf8',windowsHide:true,timeout:5000})}catch{}
 }
 stdout.write('[INFO] RELATORIO_SEM_SENHA_COPIADO\n');
}

#!/usr/bin/env node
// ROTA62 Guardian V5.1 — disposable PostgreSQL 17 restore exercise.
// LAB ONLY. pg_restore executes archive-supplied SQL; only trusted SYNTHETIC fixtures.
// Never points to production, never decrypts .r62db, never deploys.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
const fail=s=>{throw Error(s);};
const image='postgres:17';
let diagnosticStage='PRECHECK';
const marker='.rota62-guardian-lab-only';
const markerText='ROTA62_OFFLINE_LAB_V1\n';
const sleep=ms=>Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,ms);
function docker(args,{input,timeout=40000,maxBuffer=8*1024*1024}={}){
 const r=spawnSync('docker',args,{encoding:input===undefined?'utf8':null,input,timeout,maxBuffer,windowsHide:true});
 if(r.error||r.status!==0)fail('DOCKER_ACTION_FAILED');
 return typeof r.stdout==='string'?r.stdout.trim():r.stdout;
}
function dockerSafe(args){
 const r=spawnSync('docker',args,{encoding:'utf8',timeout:20000,maxBuffer:1024*1024,windowsHide:true});
 return r.status===0;
}
function parse(argv){
 const options={};
 if(argv.length!==10)fail('USAGE');
 for(let i=0;i<argv.length;i+=2){
  const k=argv[i];
  if(!['--lab-root','--fixture-dump','--fixture-sha256','--expected-tables','--mode'].includes(k)||k in options)fail('USAGE');
  options[k]=argv[i+1];
 }
 if(!['plan','exercise'].includes(options['--mode'])||!/^\d{1,3}$/.test(options['--expected-tables'])||!/^[a-f0-9]{64}$/i.test(options['--fixture-sha256']))fail('INVALID_ARGUMENTS');
 return {lab:options['--lab-root'],dump:options['--fixture-dump'],hash:options['--fixture-sha256'].toLowerCase(),tables:Number(options['--expected-tables']),mode:options['--mode']};
}
function requireLocalDocker(){
 if(process.env.DOCKER_HOST||process.env.DOCKER_CONTEXT)fail('REMOTE_DOCKER_CONTEXT_BLOCKED');
 const current=docker(['context','show']);
 if(!['default','desktop-linux'].includes(current))fail('UNKNOWN_DOCKER_CONTEXT');
 const info=JSON.parse(docker(['context','inspect',current]));
 const host=info?.[0]?.Endpoints?.docker?.Host;
 if(typeof host!=='string'||!(host.startsWith('unix://')||host.startsWith('npipe://')))fail('REMOTE_DOCKER_CONTEXT_BLOCKED');
}
function validate(o){
 for(const x of [o.lab,o.dump])if(!path.isAbsolute(x)||path.resolve(x)===path.parse(x).root)fail('INVALID_PATH');
 const lab=path.resolve(o.lab),dump=path.resolve(o.dump);
 if(fs.lstatSync(lab).isSymbolicLink()||!fs.statSync(lab).isDirectory()||fs.realpathSync(lab)!==lab)fail('LAB_INVALID');
 const file=path.join(lab,marker);
 if(fs.lstatSync(file).isSymbolicLink()||fs.readFileSync(file,'utf8')!==markerText)fail('LAB_MARKER_INVALID');
 const rel=path.relative(lab,dump);
 if(!rel||rel.startsWith('..'+path.sep)||rel==='..'||path.isAbsolute(rel))fail('FIXTURE_OUTSIDE_LAB');
 if(fs.lstatSync(dump).isSymbolicLink()||!fs.statSync(dump).isFile())fail('FIXTURE_INVALID');
 const size=fs.statSync(dump).size;
 if(size<64||size>64*1024*1024)fail('FIXTURE_SIZE_BLOCKED');
 const h=crypto.createHash('sha256'),fd=fs.openSync(dump,'r');
 try{
  const buf=Buffer.allocUnsafe(1024*1024);
  for(;;){const n=fs.readSync(fd,buf,0,buf.length,null);if(!n)break;h.update(buf.subarray(0,n));}
 }finally{fs.closeSync(fd);}
 if(h.digest('hex')!==o.hash)fail('FIXTURE_HASH_MISMATCH');
 const prefix=Buffer.alloc(5);
 const f=fs.openSync(dump,'r');try{fs.readSync(f,prefix,0,5,0);}finally{fs.closeSync(f);}
 if(prefix.toString('ascii')!=='PGDMP')fail('NOT_CUSTOM_PG_DUMP');
 requireLocalDocker();
 if(!dockerSafe(['image','inspect',image]))fail('PG17_IMAGE_NOT_PRELOADED');
 return {lab,dump,size};
}
export function exercise(o){
 const pre=validate(o);
 if(o.mode==='plan')return {mode:'plan',tables:null,created:false,cleaned:true};
 const tag='r62v51_'+crypto.randomBytes(8).toString('hex');
 const network=tag+'_net',volume=tag+'_db',container=tag+'_pg';
 const owned={net:false,vol:false,container:false};
 let result=null;
 try{
  diagnosticStage='CREATE_INTERNAL_NETWORK';
  docker(['network','create','--internal','--driver','bridge',network]);owned.net=true;
  diagnosticStage='CREATE_EPHEMERAL_VOLUME';
  docker(['volume','create',volume]);owned.vol=true;
  const pass=crypto.randomBytes(24).toString('hex');
  diagnosticStage='START_DISPOSABLE_POSTGRES';
  owned.container=true;
  docker(['run','-d','--name',container,'--network',network,'--mount','source='+volume+',target=/var/lib/postgresql/data',
    '--label','r62.guardian.lab=disposable-v51',
    '-e','POSTGRES_PASSWORD='+pass,'-e','POSTGRES_DB=restoretest',image],{timeout:60000});
  diagnosticStage='WAIT_POSTGRES';
  let ready=false;
  for(let i=0;i<40;i++){
   if(dockerSafe(['exec','--user','postgres',container,'pg_isready','-U','postgres','-d','restoretest'])){ready=true;break;}
   sleep(500);
  }
  if(!ready)fail('PG17_NOT_READY');
  // No egress network and no published ports. Do not trust Docker CLI defaults.
  diagnosticStage='INSPECT_ISOLATION';
  const ci=JSON.parse(docker(['inspect',container]))[0];
  const networks=Object.keys(ci.NetworkSettings?.Networks||{});
  if(networks.length!==1||networks[0]!==network)fail('UNEXPECTED_NETWORK');
  for(const x of Object.values(ci.NetworkSettings?.Ports||{}))if(Array.isArray(x)&&x.length)fail('PORT_PUBLISHED');
  const ni=JSON.parse(docker(['network','inspect',network]))[0];
  if(ni.Internal!==true)fail('NETWORK_NOT_INTERNAL');
  // A pg_dump custom archive is SQL-capable. Only use known synthetic dumps.
  // The bytes never leave this ephemeral docker process.
  diagnosticStage='RESTORE_SYNTHETIC_ARCHIVE';
  const bytes=fs.readFileSync(pre.dump);
  docker(['exec','-i','--user','postgres',container,'pg_restore','--exit-on-error','--single-transaction','--dbname=restoretest', '--username=postgres'],{input:bytes,timeout:180000,maxBuffer:1024*1024});
  const query="BEGIN READ ONLY; SELECT current_setting('server_version_num')||'|'||(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname<>'information_schema' AND n.nspname!~'^pg_')||'|'||(SELECT count(*) FROM pg_policy)||'|'||(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND c.relrowsecurity AND n.nspname<>'information_schema' AND n.nspname!~'^pg_')||'|'||(SELECT count(*) FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname<>'information_schema' AND n.nspname!~'^pg_'); ROLLBACK;";
  diagnosticStage='CATALOG_POSTCHECK';
  const out=docker(['exec','--user','postgres','-e','PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000',container,
    'psql','-X','-qAt','-w','-U','postgres','-d','restoretest','-v','ON_ERROR_STOP=1','-c',query]);
  const match=out.match(/^(\d+)\|(\d+)\|(\d+)\|(\d+)\|(\d+)$/m);
  if(!match||Number(match[1])<170000||Number(match[1])>=180000||Number(match[2])!==o.tables)fail('CATALOG_POSTCHECK_FAILED');
  result={mode:'exercise',tables:Number(match[2]),policies:Number(match[3]),rlsTables:Number(match[4]),indexes:Number(match[5]),created:true};
 }finally{
  // Clean only objects with unguessable names generated by THIS process.
  if(owned.container)dockerSafe(['rm','-f',container]);
  if(owned.vol)dockerSafe(['volume','rm',volume]);
  if(owned.net)dockerSafe(['network','rm',network]);
 }
 // Verify ephemeral resources are gone after cleanup; fail closed.
 diagnosticStage='VERIFY_RESOURCE_CLEANUP';
 if(dockerSafe(['container','inspect',container])||dockerSafe(['volume','inspect',volume])||dockerSafe(['network','inspect',network]))fail('RESOURCE_CLEANUP_UNVERIFIED');
 return {...result,cleaned:true};
}
function main(argv){
 const o=parse(argv),result=exercise(o);
 console.log(['=== ROTA62 GUARDIAN V5.1 DISPOSABLE PG17 RESTORE ===',
  'MODE='+o.mode.toUpperCase(),
  'FIXTURE_SHA256_VERIFIED=YES',
  'PG_DUMP_CUSTOM_HEADER_VERIFIED=YES',
  'POSTGRES17_RESTORED='+(result.created?'YES':'NO'),
  'RESTORED_TABLES='+(result.tables??'NOT_RUN'),
  'RESTORED_POLICIES='+(result.policies??'NOT_RUN'),
  'RESTORED_RLS_TABLES='+(result.rlsTables??'NOT_RUN'),
  'RESTORED_INDEXES='+(result.indexes??'NOT_RUN'),
  'ISOLATED_NETWORK=YES',
  'DOCKER_RESOURCES_CLEANED='+(result.cleaned?'YES':'NO'),
  'REAL_R62DB_DECRYPTED=NO',
  'USER_DATABASE_RESTORED=NO',
  'WEB_API_RESTORED=NO',
  'ACTUAL_RECOVERY_RTO_PROVEN=NO',
  'END_REPORT_OK'].join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main(process.argv.slice(2));}catch(e){
  const allowed=new Set(['USAGE','INVALID_ARGUMENTS','INVALID_PATH','LAB_INVALID','LAB_MARKER_INVALID','FIXTURE_OUTSIDE_LAB',
   'FIXTURE_INVALID','FIXTURE_SIZE_BLOCKED','FIXTURE_HASH_MISMATCH','NOT_CUSTOM_PG_DUMP',
   'PG17_IMAGE_NOT_PRELOADED','REMOTE_DOCKER_CONTEXT_BLOCKED','UNKNOWN_DOCKER_CONTEXT','DOCKER_ACTION_FAILED','PG17_NOT_READY','UNEXPECTED_NETWORK','PORT_PUBLISHED',
   'NETWORK_NOT_INTERNAL','CATALOG_POSTCHECK_FAILED','RESOURCE_CLEANUP_UNVERIFIED']);
  console.log('=== ROTA62 GUARDIAN V5.1 DISPOSABLE PG17 RESTORE ===\nSTATUS=BLOCKED_'+(allowed.has(e.message)?e.message:'REDACTED')+'\nFAILED_AT='+diagnosticStage+
  '\nPRODUCTION_TOUCHED=NO\nREAL_R62DB_DECRYPTED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

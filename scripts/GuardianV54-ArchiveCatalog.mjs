#!/usr/bin/env node
/**
 * Guardian V5.4 — Authenticated pg_restore TOC inspection in isolated Docker (no SQL).
 * R62DB02 envelope based on the ORIGINAL operator-supplied backup-postgres.mjs v1.4.4.
 * Two passes: first verify entire AES-GCM auth tag; second decrypt and feed PGDMP
 * to pg_restore --list inside a disposable --network none / --read-only container.
 * No plaintext file, no database container, no secrets or network; no production writes.
 */
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {authenticate} from './GuardianV53-AuthenticateR62DB.mjs';
import {inspectToc} from './GuardianV64-TocDependencyPreflight.mjs';
import {auditTocShape} from './GuardianV65-TocShapeRiskAudit.mjs';
import {auditTocBlindSpots} from './GuardianV66-TocBlindSpotAudit.mjs';
import {auditTableScope} from './GuardianV67-TableScopeAudit.mjs';
import {auditTocTableDataPairs} from './GuardianV68-TableDataPairAudit.mjs';

const fail=x=>{throw Error(x)};
const MAGIC=Buffer.from('R62DB02\n','ascii');
const EXPECTED_TABLES=76;
const KDF={N:32768,r:8,p:1,maxmem:128*1024*1024};
const MAX_ENCRYPTED=1024*1024*1024;
function cliOptions(argv){
 if(![6,7].includes(argv.length)||argv[0]!=='--archive'||argv[2]!=='--expected-sha256'||argv[4]!=='--report-file'||(argv.length===7&&argv[6]!=='--deep-read'))fail('USAGE');
 if(!path.isAbsolute(argv[1])||!/^[a-f0-9]{64}$/i.test(argv[3])||!path.isAbsolute(argv[5]))fail('USAGE');
 return {archive:argv[1],sha:argv[3].toLowerCase(),report:argv[5],deepRead:argv.length===7};
}
const RESTORED_CONTAINERS=['44fc8a2a3995','529fc3927b48','4645575c1617','9576b226ca0a'];
let verifiedImage=null;
function dockerProbe(args,timeout=12000){
 const r=spawnSync('docker',args,{encoding:'utf8',timeout,windowsHide:true,maxBuffer:1024*1024});
 return r.status===0?String(r.stdout).trim():null;
}
function localDocker(){
 if(verifiedImage)return verifiedImage;
 if(process.env.DOCKER_HOST||process.env.DOCKER_CONTEXT)fail('REMOTE_DOCKER_CONTEXT');
 const context=dockerProbe(['context','show']);
 if(!['default','desktop-linux'].includes(context))fail('DOCKER_CONTEXT_BLOCKED');
 const raw=dockerProbe(['context','inspect',context]);
 let ctx;try{ctx=JSON.parse(raw);}catch{fail('DOCKER_CONTEXT_BLOCKED');}
 const host=ctx?.[0]?.Endpoints?.docker?.Host;
 if(typeof host!=='string'||!(host.startsWith('npipe://')||host.startsWith('unix://')))fail('DOCKER_CONTEXT_BLOCKED');
 const candidates=['postgres:17','postgres:17-alpine','postgres:17-bookworm'];
 for(const id of RESTORED_CONTAINERS){
  const info=dockerProbe(['inspect','--type','container',id]);
  if(!info)continue;
  let item;try{item=JSON.parse(info)?.[0];}catch{continue;}
  // Only pre-existing, identified isolated Postgres restoration containers.
  if(item?.State?.Running===true&&item?.Id?.startsWith(id)&&typeof item.Image==='string'&&
     /^sha256:[a-f0-9]{64}$/.test(item.Image)&&
     String(item.Config?.Image).toLowerCase().includes('postgres')&&
     Array.isArray(item.Mounts)&&item.Mounts.length===1&&item.Mounts[0].Type==='volume'&&
     Object.values(item.NetworkSettings?.Ports||{}).every(x=>!Array.isArray(x)||x.length===0)){
    candidates.push(item.Image);
  }
 }
 for(const candidate of [...new Set(candidates)]){
  const imageId=dockerProbe(['image','inspect','--format','{{.Id}}',candidate]);
  if(!imageId||!/^sha256:[a-f0-9]{64}$/.test(imageId))continue;
  // Verify the executable using the immutable content-addressed image ID.
  // A local tag can otherwise move between the preflight and the data read.
  const version=dockerProbe(['run','--rm','--pull','never','--network','none','--read-only',
    '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','32',
    '--memory','128m','--cpus','1','--user','999:999',
    '--entrypoint','pg_restore',imageId,'--version'],25000);
  if(version&&/pg_restore \(PostgreSQL\) 17(?:\.|\s|$)/.test(version)){
   verifiedImage=imageId;
   return verifiedImage;
  }
 }
 fail('PG17_LOCAL_IMAGE_NOT_FOUND');
}
function header(file){
 const st=fs.lstatSync(file);
 if(!st.isFile()||st.isSymbolicLink()||st.size<64||st.size>MAX_ENCRYPTED)fail('INVALID_ARCHIVE');
 const fd=fs.openSync(file,'r');
 try{
  const p=Buffer.alloc(12);
  if(fs.readSync(fd,p,0,12,0)!==12||!p.subarray(0,8).equals(MAGIC))fail('BAD_MAGIC');
  const len=p.readUInt32BE(8);
  if(len<16||len>4096||st.size<=12+len+16)fail('BAD_HEADER');
  const raw=Buffer.alloc(len);
  if(fs.readSync(fd,raw,0,len,12)!==len)fail('BAD_HEADER');
  let j;try{j=JSON.parse(raw.toString('utf8'));}catch{fail('BAD_HEADER');}
  if(j.schema!==2||j.format!=='pg_dump_custom'||j.cipher!=='AES-256-GCM'||j.kdf!=='scrypt'||j.N!==32768||j.r!==8||j.p!==1||!/^[a-f0-9]{32}$/.test(j.salt)||!/^[a-f0-9]{24}$/.test(j.nonce))fail('UNSUPPORTED_HEADER');
  const tag=Buffer.alloc(16);fs.readSync(fd,tag,0,16,st.size-16);
  return {head:j,aad:Buffer.concat([p,raw]),tag,start:12+len,end:st.size-17};
 }finally{fs.closeSync(fd);}
}
function passwordTTY(){
 if(!process.stdin.isTTY||!process.stdin.setRawMode)fail('TTY_REQUIRED');
 return new Promise((yes,no)=>{
  let val='',done=false;
  const restore=process.stdin.isRaw;
  const stop=(err)=>{
   if(done)return;done=true;process.stdin.off('data',onData);
   process.stdin.setRawMode(Boolean(restore));process.stdin.pause();
   process.stdout.write('\n');
   err?no(err):yes(val);
  };
  const onData=(b)=>{
   for(const ch of b.toString('utf8')){
    if(ch==='\u0003'){stop(Error('CANCELLED'));return;}
    if(ch==='\r'||ch==='\n'){stop();return;}
    if(ch==='\u007f'||ch==='\b'){if(val){val=val.slice(0,-1);process.stdout.write('\b \b');}continue;}
    if(ch>=' '&&val.length<1024){val+=ch;process.stdout.write('*');}
   }
  };
  process.stdout.write('Senha local do backup (sem eco): ');
  process.stdin.setRawMode(true);process.stdin.resume();process.stdin.on('data',onData);
 });
}
function classifyTOC(s){
 const lines=s.split(/\r?\n/);
 const rows=lines.filter(l=>/^\s*\d+;\s+\d+\s+\d+\s+/.test(l));
 if(rows.length<5)fail('TOC_UNEXPECTEDLY_SMALL');
 const counts={};
 // Type labels are conservative, don't interpret object/role names.
 for(const l of rows){
  const tail=l.replace(/^\s*\d+;\s+\d+\s+\d+\s+/,'');
  let kind='OTHER';
  for(const candidate of ['DEFAULT ACL','TABLE DATA','FK CONSTRAINT','ROW SECURITY','MATERIALIZED VIEW','SEQUENCE SET','SEQUENCE OWNED BY',
    'TABLE','SCHEMA','FUNCTION','PROCEDURE','POLICY','INDEX','TRIGGER','EXTENSION','TYPE','ACL','SEQUENCE','CONSTRAINT','VIEW','COMMENT']){
   if(tail.startsWith(candidate+' ')){kind=candidate.replaceAll(' ','_');break;}
  }
  counts[kind]=(counts[kind]||0)+1;
 }
 return {items:rows.length,counts};
}
function ciphertextHash(file){
 return new Promise((resolve,reject)=>{
  const h=crypto.createHash('sha256');
  const stream=fs.createReadStream(file);
  stream.on('error',()=>reject(Error('CIPHERTEXT_RECHECK_FAILED')));
  stream.on('data',buf=>h.update(buf));
  stream.on('end',()=>resolve(h.digest('hex')));
 });
}
export function decodeTocUtf8Chunks(chunks){
 if(!Array.isArray(chunks)||chunks.some(c=>!Buffer.isBuffer(c)))
  fail('TOC_ENCODING_SOURCE_INVALID');
 const total=chunks.reduce((sum,c)=>sum+c.length,0);
 if(total>8*1024*1024)fail('TOC_OUTPUT_TOO_LARGE');
 try{return new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,total));}
 catch{fail('TOC_TEXT_ENCODING_INVALID');}
}
export function verifyPg17PatchVersion(version){
 const m=/^pg_restore \(PostgreSQL\) 17\.(\d+)(?: \((?:Debian|Ubuntu) [A-Za-z0-9.+:~_-]{1,96}\))?$/.exec((version||'').trim());
 if(!m||Number(m[1])<12)fail('PG17_PATCH_LEVEL_BLOCKED');
 return true;
}
function deepReadPatchGate(image){
 const version=dockerProbe(['run','--rm','--pull','never','--network','none',
  '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
  '--pids-limit','32','--memory','128m','--cpus','1','--user','999:999',
  '--entrypoint','pg_restore',image,'--version'],25000);
 return verifyPg17PatchVersion(version);
}
async function pgRestoreFromEncrypted(file,passwd,expectedCipherSha,expectedPlainSha,mode='toc'){
 if(!['toc','full'].includes(mode))fail('UNSAFE_RESTORE_MODE');
 const selectedImage=localDocker();
 if(mode==='full')deepReadPatchGate(selectedImage);
 const m=header(file);
 const key=crypto.scryptSync(passwd,Buffer.from(m.head.salt,'hex'),32,KDF);
 let child=null,stdout='',badOutput=false,failed=false,skippedOutputBytes=0,watchdog=null;
 let stderrObserved=false,timedOut=false;
 const stdoutChunks=[];let stdoutBytes=0;
 const ownedName='r62-guardian-read-'+crypto.randomBytes(8).toString('hex');
 const ownership=crypto.randomBytes(16).toString('hex');
 const secondPlainHash=crypto.createHash('sha256');
 try{
  const args=['run','--rm','-i','--pull','never','--network','none','--read-only',
   '--name',ownedName,'--label','r62.guardian.owner='+ownership,
   '--cap-drop','ALL','--security-opt','no-new-privileges','--pids-limit','64','--memory','256m',
   '--cpus','1','--user','999:999','--tmpfs','/tmp:rw,noexec,nosuid,size=16m',
   '--entrypoint','pg_restore',selectedImage,...(mode==='full'?['--file=/dev/null']:['--list'])];
  child=spawn('docker',args,{stdio:['pipe','pipe','pipe'],windowsHide:true,env:{...process.env,DOCKER_HOST:undefined,DOCKER_CONTEXT:undefined}});
  watchdog=setTimeout(()=>{timedOut=true;if(child&&!child.killed)child.kill();},mode==='full'?360000:90000);
  // Resolve rather than rejecting immediately: no transient unhandled promise
  // on failed Docker startup while the authenticated input stream is unwinding.
  const done=new Promise(resolve=>{
   child.on('error',()=>resolve(-1));
   child.on('close',code=>resolve(code??-1));
  });
  child.stdout.on('data',buf=>{
   if(mode==='full'){badOutput=true;return;}
   // Decode only after all chunks: otherwise UTF-8 codepoints split at a
   // pipe boundary get U+FFFD and can silently corrupt object identity.
   stdoutBytes+=buf.length;
   if(stdoutBytes>8*1024*1024)badOutput=true;
   else stdoutChunks.push(buf);
  });
  child.stderr.on('data',()=>{stderrObserved=true;}); // Count only; never expose object names or raw warnings.
  child.stdin.on('error',()=>{}); // pg_restore may stop reading after TOC; ciphertext still authenticated separately.
  const decipher=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(m.head.nonce,'hex'));
  decipher.setAAD(m.aad);decipher.setAuthTag(m.tag);
  const decrypted=fs.createReadStream(file,{start:m.start,end:m.end}).pipe(decipher);
  try{
   for await(const chunk of decrypted){
    secondPlainHash.update(chunk);
    if(child.stdin.writable&&!child.stdin.destroyed){
     if(!child.stdin.write(chunk)){
      await new Promise(resolve=>{
       const finish=()=>{
        child.stdin.off('drain',finish);child.stdin.off('close',finish);
        child.stdin.off('error',finish);resolve();
       };
       child.stdin.once('drain',finish);child.stdin.once('close',finish);
       child.stdin.once('error',finish);
      });
     }
    }else if(mode==='full'){skippedOutputBytes+=chunk.length;}
   }
  }catch{failed=true;}
  if(!child.stdin.destroyed)child.stdin.end();
  const exit=await done;
  clearTimeout(watchdog);watchdog=null;
  if(failed)fail('SECOND_PASS_AUTHENTICATION_FAILED');
  if(exit!==0||timedOut||stderrObserved||badOutput||(mode==='full'&&skippedOutputBytes>0))
   fail(mode==='full'?'PG_RESTORE_FULL_READ_FAILED':'PG_RESTORE_LIST_FAILED');
  // Second pass must still be the exact authenticated archive: reject a
  // concurrent swap to another valid AES-GCM envelope or a mid-read mutation.
  if(secondPlainHash.digest('hex')!==expectedPlainSha||
     await ciphertextHash(file)!==expectedCipherSha)
    fail('CIPHERTEXT_CHANGED_BETWEEN_PASSES');
  if(mode==='full')return {fullRead:true,sqlExecuted:false,rowsValidated:false};
  stdout=decodeTocUtf8Chunks(stdoutChunks);
  const catalog=classifyTOC(stdout);
  const dependencySummary=inspectToc(stdout);
  const shapeAudit=auditTocShape(stdout);
  const blindSpotAudit=auditTocBlindSpots(stdout);
  const tableScopeAudit=auditTableScope(stdout);
  const tableDataPairs=auditTocTableDataPairs(stdout);
  if(catalog.items!==dependencySummary.entries||catalog.items!==shapeAudit.entries||
    catalog.items!==blindSpotAudit.entries||
    catalog.items!==tableScopeAudit.catalogItems||
    catalog.items!==tableDataPairs.entries||
    (catalog.counts.TABLE||0)!==tableDataPairs.tableEntries||
    (catalog.counts.TABLE_DATA||0)!==tableDataPairs.dataEntries||
    tableDataPairs.structurallyPaired+tableDataPairs.unpairedSimpleTableEntries+
    tableDataPairs.ambiguousTableEntries!==tableDataPairs.tableEntries||
    tableDataPairs.structurallyPaired+tableDataPairs.unpairedSimpleDataEntries+
    tableDataPairs.ambiguousDataEntries!==tableDataPairs.dataEntries||
    (catalog.counts.TABLE||0)!==tableScopeAudit.tableEntries||
    (catalog.counts.TABLE_DATA||0)!==tableScopeAudit.tableDataEntries||
    tableScopeAudit.publicSchemaTableEntries+
    tableScopeAudit.otherSimpleSchemaTableEntries+
    tableScopeAudit.noSchemaTableEntries+
    tableScopeAudit.complexOrAmbiguousSchemaTableEntries!==tableScopeAudit.tableEntries||
    catalog.counts.EXTENSION!==shapeAudit.extensionEntries||
    shapeAudit.unrecognizedTypes!==blindSpotAudit.v65Unrecognized||
    shapeAudit.nonstandardLastTokens!==blindSpotAudit.v65NonstandardLastTokens)
    fail('TOC_AUDIT_COUNTER_INCONSISTENT');
  return {...catalog,dependencySummary,shapeAudit,blindSpotAudit,tableScopeAudit,tableDataPairs};
 }finally{
  if(watchdog)clearTimeout(watchdog);
  key.fill(0);
  if(child&&!child.killed&&child.exitCode===null)child.kill();
  // Clean only an owned disposable container. Never remove CLEAN6 or any
  // existing container; the random label must match the current invocation.
  const label=dockerProbe(['inspect','--type','container','--format',
   '{{index .Config.Labels "r62.guardian.owner"}}',ownedName],6000);
  if(label===ownership)dockerProbe(['rm','-f',ownedName],12000);
 }
}
export async function examine(file,sha,password,options={}){
 const auth=await authenticate(file,sha,password);
 if(auth.bytes<32)fail('INVALID_PLAINTEXT');
 const toc=await pgRestoreFromEncrypted(file,password,sha.toLowerCase(),auth.plainSha256,'toc');
 const deepRead=options.deepRead===true?
  await pgRestoreFromEncrypted(file,password,sha.toLowerCase(),auth.plainSha256,'full'):null;
 return {auth,toc,deepRead};
}
// Pure report contract, shared by authenticated production path and synthetic tests.
// Contains only fixed whitelisted labels, numeric counters, and fixed-length digests.
export function renderSafeCatalogReport(result){
 const lines=['=== ROTA62 GUARDIAN V5.4 AUTHENTICATED PG_RESTORE CATALOG ===',
  'CIPHERTEXT_SHA256_MATCH=YES','AES_GCM_TAG_AUTHENTICATED=YES',
  'LOCAL_PG17_IMAGE_VERIFIED=YES',
  'DECRYPTED_PG_CUSTOM_HEADER=YES','PG_RESTORE_CATALOG=PASS',
  'ARCHIVE_CONTENT_SHA16='+result.auth.plainSha256.slice(0,16).toUpperCase(),
  'ARCHIVE_CATALOG_ITEMS='+result.toc.items,
  'DEPENDENCY_VISIBLE_OWNER_ROLES='+result.toc.dependencySummary.distinctVisibleOwnerRoles,
  'DEPENDENCY_DISTINCT_EXTENSIONS='+result.toc.dependencySummary.distinctExtensions,
  'DEPENDENCY_UNCLASSIFIED_TOC_ENTRIES='+result.toc.dependencySummary.unclassifiedEntries,
  'DEPENDENCY_AMBIGUOUS_TOC_OWNER_ENTRIES='+result.toc.dependencySummary.ambiguousOwner,
  'DEPENDENCY_SHA16='+result.toc.dependencySummary.dependencyFingerprint16,
  'DEPENDENCY_ROLE_GRANTEES_COMPLETE=NO',
  'SHAPE_RECOGNIZED_TYPES='+result.toc.shapeAudit.recognizedTypes,
  'SHAPE_UNRECOGNIZED_TYPES='+result.toc.shapeAudit.unrecognizedTypes,
  'SHAPE_NO_OWNER_PROOF_ITEMS='+result.toc.shapeAudit.typesWithoutOwnerProof,
  'SHAPE_OWNER_CANDIDATE_ONLY_ITEMS='+result.toc.shapeAudit.structuralOwnerCandidatesOnly,
  'SHAPE_NONSTANDARD_LAST_TOKENS='+result.toc.shapeAudit.nonstandardLastTokens,
  'SHAPE_HISTORICAL_GLOBAL_ROLES_VERIFIED=NO',
  'BLIND_KNOWN_PUBLIC_KIND_ITEMS='+result.toc.blindSpotAudit.recognizedPublicPgKindsNotInV65,
  'BLIND_OTHER_UNKNOWN_SHAPES='+result.toc.blindSpotAudit.otherUnknownShapes,
  'BLIND_NONSTANDARD_CANDIDATE_ITEMS='+result.toc.blindSpotAudit.nonstandardInCandidateOnlyTypes,
  'BLIND_NONSTANDARD_NO_PROOF_ITEMS='+result.toc.blindSpotAudit.nonstandardInNoOwnerProofTypes,
  'BLIND_HISTORICAL_GLOBAL_ROLES_VERIFIED=NO',
  'SCOPE_PUBLIC_SCHEMA_TABLES='+result.toc.tableScopeAudit.publicSchemaTableEntries,
  'SCOPE_OTHER_SIMPLE_SCHEMA_TABLES='+result.toc.tableScopeAudit.otherSimpleSchemaTableEntries,
  'SCOPE_NO_SCHEMA_TABLES='+result.toc.tableScopeAudit.noSchemaTableEntries,
  'SCOPE_COMPLEX_SCHEMA_TABLES='+result.toc.tableScopeAudit.complexOrAmbiguousSchemaTableEntries,
  'SCOPE_ORIGINAL_USER_TABLES_VALIDATED=NO',
  'AUDIT_PROFILE=V68_STRUCTURAL_TABLE_DATA',
  'PAIR_STRUCTURALLY_MATCHED='+result.toc.tableDataPairs.structurallyPaired,
  'PAIR_UNPAIRED_SIMPLE_TABLE='+result.toc.tableDataPairs.unpairedSimpleTableEntries,
  'PAIR_UNPAIRED_SIMPLE_DATA='+result.toc.tableDataPairs.unpairedSimpleDataEntries,
  'PAIR_AMBIGUOUS_TABLE='+result.toc.tableDataPairs.ambiguousTableEntries,
  'PAIR_AMBIGUOUS_DATA='+result.toc.tableDataPairs.ambiguousDataEntries,
  'PAIR_DUPLICATE_NONUNIQUE='+result.toc.tableDataPairs.duplicateOrNonUniqueEntries,
  'PAIR_ROWS_VERIFIED=NO'];
 if(result.deepRead){
  lines.push('DEEP_FULL_ARCHIVE_READ=PASS');
  lines.push('DEEP_ROWS_VALIDATED=NO');
  lines.push('DEEP_SQL_EXECUTED=NO');
 }
 // Explicit zeros preserve strict V5.5 parser compatibility for small synthetic
 // and future archives, without weakening its required-field checks.
 const tocCounts={...result.toc.counts};
 for(const kind of ['TABLE','TABLE_DATA','EXTENSION','FUNCTION','ACL',
  'DEFAULT_ACL','POLICY','ROW_SECURITY','TRIGGER','INDEX'])
  if(!Object.hasOwn(tocCounts,kind))tocCounts[kind]=0;
 for(const [k,v] of Object.entries(tocCounts).sort())lines.push('TOC_'+k+'='+v);
 lines.push('EXPECTED_USER_TABLES_REFERENCE='+EXPECTED_TABLES);
 lines.push('CATALOG_COUNTS_DO_NOT_VALIDATE_DATA=YES');
 lines.push('PG_RESTORE_EXECUTED_SQL=NO');
 lines.push('DATABASE_RESTORED=NO','ROLES_ACL_RESTORED=NO');
 lines.push('ARCHIVE_PLAINTEXT_FILE_WRITTEN=NO','PRODUCTION_TOUCHED=NO');
 lines.push('RTO_4_TO_6_HOURS_PROVEN=NO','END_REPORT_OK');
 return lines.join('\n');
}
export async function main(argv){
 const p=cliOptions(argv);
 // Fail closed before password. Never execute archiver until full GCM authentication.
 const image=localDocker(); // No password prompt unless a local, preloaded PG17 runtime exists.
 if(p.deepRead)deepReadPatchGate(image);
 const pass=await passwordTTY();
 const result=await examine(p.archive,p.sha,pass,{deepRead:p.deepRead});
 const report=renderSafeCatalogReport(result);
 fs.writeFileSync(p.report,report+'\n',{flag:'wx',mode:0o600});
 console.log(report);
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 main(process.argv.slice(2)).catch(err=>{
  const known=new Set(['USAGE','REMOTE_DOCKER_CONTEXT','DOCKER_CONTEXT_BLOCKED','PG17_IMAGE_NOT_PRELOADED','PG17_LOCAL_IMAGE_NOT_FOUND',
   'INVALID_ARCHIVE','BAD_MAGIC','BAD_HEADER','UNSUPPORTED_HEADER','TTY_REQUIRED','CANCELLED',
   'PG_RESTORE_LIST_FAILED','PG_RESTORE_FULL_READ_FAILED','PG17_PATCH_LEVEL_BLOCKED','TOC_UNEXPECTEDLY_SMALL','SECOND_PASS_AUTHENTICATION_FAILED','CIPHERTEXT_CHANGED_BETWEEN_PASSES']);
  const report=['=== ROTA62 GUARDIAN V5.4 AUTHENTICATED PG_RESTORE CATALOG ===',
   'STATUS=BLOCKED_'+(known.has(err.message)?err.message:'ERROR_REDACTED'),
   'NO_DATABASE_SQL_EXECUTED=YES','PRODUCTION_TOUCHED=NO','END_REPORT_OK'].join('\n');
  const args=process.argv.slice(2);
  if([6,7].includes(args.length)&&args[4]==='--report-file'&&path.isAbsolute(args[5])){
   try{fs.writeFileSync(args[5],report+'\n',{flag:'wx',mode:0o600});}catch{}
  }
  console.log(report);process.exitCode=2;
 });
}

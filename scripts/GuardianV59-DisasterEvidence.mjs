#!/usr/bin/env node
// ROTA62 Guardian V5.9 — no-write cross-component disaster readiness evidence gate.
// Verifies 7 existing source snapshots, independent 6-component stage, and a separately
// provided GLOBALS artifact. SHA checks are INTEGRITY, not origin/authenticity.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {parseConfig,verify} from './GuardianV4-Coverage.mjs';
import {verifyStage} from './GuardianV5-VerifyStage.mjs';
const fail=x=>{throw Error(x);};
const MAX_CONFIG=2*1024*1024,MAX_GLOBALS=20*1024*1024;
const HASH=/^[a-f0-9]{64}$/i;
function loadBytes(file,max){
 if(!path.isAbsolute(file)||path.resolve(file)===path.parse(file).root)fail('INPUT_PATH_INVALID');
 const stat=fs.lstatSync(file);
 if(stat.isSymbolicLink()||!stat.isFile()||stat.size<1||stat.size>max)fail('INPUT_INVALID');
 return fs.readFileSync(file);
}
function hexHash(buffer){return crypto.createHash('sha256').update(buffer).digest('hex');}
function stageHash(dir){
 const file=path.join(dir,'manifest.json');
 if(!fs.lstatSync(file).isFile()||fs.lstatSync(file).isSymbolicLink())fail('STAGE_MANIFEST_INVALID');
 const m=JSON.parse(fs.readFileSync(file,'utf8'));
 return m.encryptedDatabaseSha256?.toLowerCase();
}
export function audit({config,stage,globals,globalsSha256}){
 if(!HASH.test(globalsSha256||''))fail('GLOBALS_REFERENCE_INVALID');
 if(!path.isAbsolute(stage)||!path.isAbsolute(config)||!path.isAbsolute(globals))fail('INPUT_PATH_INVALID');
 const cfg=parseConfig(loadBytes(config,MAX_CONFIG).toString('utf8'));
 const seven=verify(cfg);
 if(!seven.complete)fail('SEVEN_COMPONENTS_BLOCKED');
 const staged=verifyStage(stage);
 const expected=cfg.components.database.sha256.toLowerCase();
 if(stageHash(stage)!==expected)fail('SNAPSHOT_IDENTITY_MISMATCH');
 const vault=fs.realpathSync(cfg.components['secrets-vault'].path);
 const roots=[fs.realpathSync(config),fs.realpathSync(globals)];
 const stageRoot=fs.realpathSync(stage);
 const overlaps=(a,b)=>a===b||a.startsWith(b+path.sep)||b.startsWith(a+path.sep);
 if(roots.some(x=>overlaps(x,stageRoot))||overlaps(vault,stageRoot))fail('SOURCE_STAGE_OVERLAP');
 const bytes=loadBytes(globals,MAX_GLOBALS);
 if(hexHash(bytes)!==globalsSha256.toLowerCase())fail('GLOBALS_HASH_MISMATCH');
 // Unlike an actual globals restore, we NEVER parse or execute this SQL.
 // Its origin, content and administrative safety require independent human review.
 return {sourceComponents:seven.results.length,stagedComponents:6,
  stagedFiles:staged.files,globalsBytes:bytes.length,databaseSha16:expected.slice(0,16).toUpperCase()};
}
function args(argv){
 if(argv.length!==8)fail('USAGE');
 const m=new Map();
 for(let i=0;i<argv.length;i+=2){
  if(!['--config','--stage','--globals','--globals-sha256'].includes(argv[i])||m.has(argv[i]))fail('USAGE');
  m.set(argv[i],argv[i+1]);
 }
 if(m.size!==4)fail('USAGE');
 return {config:m.get('--config'),stage:m.get('--stage'),globals:m.get('--globals'),globalsSha256:m.get('--globals-sha256')};
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const result=audit(args(process.argv.slice(2)));
  console.log(['=== ROTA62 GUARDIAN V5.9 DISASTER EVIDENCE ===',
    'SOURCE_COMPONENTS='+result.sourceComponents+'/7',
    'STAGED_COMPONENTS='+result.stagedComponents+'/6',
    'STAGED_FILES='+result.stagedFiles,
    'DATABASE_CIPHERTEXT_REFERENCE_SHA16='+result.databaseSha16,
    'GLOBALS_FILE_SHA256_VERIFIED=YES',
    'GLOBALS_FILE_BYTES='+result.globalsBytes,
    'GLOBALS_SOURCE_PROVENANCE_ATTESTED=NO',
    'GLOBALS_ROLE_SEMANTICS_AUDITED=NO',
    'GLOBALS_EXECUTED=NO','SECRETS_VAULT_COPIED=NO',
    'APPLICATION_END_TO_END_RECOVERY_TESTED=NO',
    'REAL_DATABASE_RESTORED=NO','RECOVERY_READY=NO',
    'PRODUCTION_TOUCHED=NO','RTO_4_TO_6_HOURS_PROVEN=NO','END_REPORT_OK'].join('\n'));
 }catch(e){
  const codes=new Set(['USAGE','GLOBALS_REFERENCE_INVALID','INPUT_PATH_INVALID','INPUT_INVALID',
   'SEVEN_COMPONENTS_BLOCKED','STAGE_MANIFEST_INVALID','SNAPSHOT_IDENTITY_MISMATCH',
   'SOURCE_STAGE_OVERLAP','GLOBALS_HASH_MISMATCH']);
  console.log('=== ROTA62 GUARDIAN V5.9 DISASTER EVIDENCE ===\nSTATUS=BLOCKED_'+
   (codes.has(e.message)?e.message:'REDACTED')+
   '\nPRODUCTION_TOUCHED=NO\nREAL_DATABASE_RESTORED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

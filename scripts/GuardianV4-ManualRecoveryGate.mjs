#!/usr/bin/env node
// ROTA62 Guardian V4: manual pre-update verification and disaster readiness gate.
// This never creates/restores backups or reaches production. All private data stays on disk.
import {readFileSync,statSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parseConfig,verify} from './GuardianV4-Coverage.mjs';
const fail=x=>{throw Error(x);};
const actions=new Set(['pre-update','restore-readiness']);
const allowed=new Set(['--action','--config','--max-age-hours','--test-report']);
function parse(argv){
 const args={};
 if(!argv.length||argv.length%2)fail('USAGE');
 for(let i=0;i<argv.length;i+=2){
  if(!allowed.has(argv[i])||args[argv[i]]!==undefined)fail('USAGE');
  args[argv[i]]=argv[i+1];
 }
 if(!actions.has(args['--action'])||typeof args['--config']!=='string'||!args['--config'])fail('USAGE');
 if(args['--max-age-hours']!==undefined&&!/^(?:[1-9]|[1-9]\d|1\d\d)$/.test(args['--max-age-hours']))fail('INVALID_AGE');
 return {action:args['--action'],config:args['--config'],maxAgeHours:Number(args['--max-age-hours']??'24'),testReport:args['--test-report']};
}
function safeReport(s){
 let obj;try{obj=JSON.parse(readFileSync(s,'utf8'));}catch{fail('INVALID_TEST_REPORT');}
 // A separate independent proof must have been obtained by a trusted test runner.
 // This input is not cryptographically attested; merely a declaration from the operator.
 const good=obj&&obj.format==='r62-guardian-rehearsal-evidence-v1'&&
  obj.outcome==='PASS'&&Number.isFinite(obj.durationMinutes)&&obj.durationMinutes>=0&&obj.durationMinutes<=360&&
  typeof obj.completedUtc==='string'&&!Number.isNaN(Date.parse(obj.completedUtc))&&
  typeof obj.backupSha256==='string'&&/^[0-9a-f]{64}$/i.test(obj.backupSha256);
 if(!good)fail('INVALID_TEST_REPORT');
 return obj;
}
export function evaluate(cfg,options,now=Date.now()){
 const check=verify(cfg);
 const first=cfg.components.database;
 let fileAgeHours=null,ageOk=false;
 try{
  const s=statSync(first.path);
  fileAgeHours=Math.max(0,(now-s.mtimeMs)/3600000);
  ageOk=(s.mtimeMs<=now+300000)&&fileAgeHours<=options.maxAgeHours;
 }catch{}
 let reportedTest=false,reportAgeHours=null,matchingHash=false;
 if(options.testReport){
  try{
   const report=safeReport(options.testReport);
   reportAgeHours=(now-Date.parse(report.completedUtc))/3600000;
   reportedTest=reportAgeHours>=0&&reportAgeHours<=24*30;
   matchingHash=report.backupSha256.toLowerCase()===first.sha256.toLowerCase();
  }catch{}
 }
 // Rehearsal is operator declared, not attested or personally verified by this script.
 const readyForManualPreUpdate=check.complete&&ageOk;
 const restoreEvidence=check.complete&&reportedTest&&matchingHash;
 return {check,ageOk,fileAgeHours,reportedTest,matchingHash,reportAgeHours,readyForManualPreUpdate,restoreEvidence};
}
export function main(argv){
 const options=parse(argv);
 const cfg=parseConfig(readFileSync(options.config,'utf8'));
 const r=evaluate(cfg,options);
 const out=['=== ROTA62 GUARDIAN V4 MANUAL RECOVERY GATE ===',
  'ACTION='+options.action.toUpperCase().replaceAll('-','_'),
  'AUTO_BACKUP_SCHEDULED=NO',
  'COMPONENTS_VERIFIED='+r.check.results.length+'/7',
  'COMPONENTS_MISSING_OR_INVALID='+r.check.blocked.length,
  'ENCRYPTED_DATABASE_HASH_MATCH='+(r.check.results.some(x=>x.component==='database')?'YES':'NO'),
  'DB_FILE_AGE_WITHIN_MAX_HOURS='+(r.ageOk?'YES':'NO'),
  'RECOVERY_REHEARSAL_DECLARED='+(r.reportedTest?'YES':'NO'),
  'REHEARSAL_MATCHES_DATABASE_HASH='+(r.matchingHash?'YES':'NO'),
  'RECOVERY_RTO_TARGET_HOURS=4_TO_6'];
 for(const item of r.check.blocked)out.push('BLOCKED_COMPONENT_'+item.component.toUpperCase().replaceAll('-','_')+'=YES');
 if(options.action==='pre-update'){
  out.push('PRE_UPDATE_VERIFICATION_GATE='+(r.readyForManualPreUpdate?'PASS':'BLOCKED'));
  out.push('PUBLISH_AUTHORIZED=NO');
 }else{
  out.push('RECOVERY_EVIDENCE_GATE='+(r.restoreEvidence?'DECLARED_PASS':'BLOCKED'));
  out.push('RECOVERY_TEST_IS_SELF_ATTESTED=NO');
  out.push('AUTOMATED_RESTORE_IMPLEMENTED=NO');
 }
 out.push('NO_PRODUCTION_ACTIONS_PERFORMED=YES');
 out.push('DATABASE_ROWS_NOT_QUERIED=YES');
 out.push('BACKUP_NOT_CREATED_OR_MODIFIED=YES');
 out.push('END_REPORT_OK');
 console.log(out.join('\n'));
 // A gate may pass only for file presence, byte checks and local recency, not for deploy.
 if(options.action==='pre-update'&&!r.readyForManualPreUpdate)process.exitCode=2;
 if(options.action==='restore-readiness'&&!r.restoreEvidence)process.exitCode=2;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main(process.argv.slice(2));}
 catch(e){
  const code=['USAGE','INVALID_AGE','INVALID_TEST_REPORT'].includes(e.message)?e.message:'BLOCKED_REDACTED';
  console.log('=== ROTA62 GUARDIAN V4 MANUAL RECOVERY GATE ===\nSTATUS='+code+'\nNO_PRODUCTION_ACTIONS_PERFORMED=YES\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

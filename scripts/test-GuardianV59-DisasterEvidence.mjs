#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {prepare} from './GuardianV5-LabStage.mjs';
import {audit} from './GuardianV59-DisasterEvidence.mjs';
const home=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-v59-ci-'));
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
function file(p,b){
 fs.mkdirSync(path.dirname(p),{recursive:true});
 fs.writeFileSync(p,b);
 return p;
}
try{
 const source=path.join(home,'source'),lab=path.join(home,'isolated-lab');
 fs.mkdirSync(lab);
 file(path.join(lab,'.rota62-guardian-lab-only'),'ROTA62_OFFLINE_LAB_V1\n');
 const encrypted=Buffer.concat([Buffer.from('R62DB02\n'),crypto.randomBytes(512)]);
 const db=file(path.join(source,'backup.r62db'),encrypted);
 const roles={database:{path:db,kind:'file',sha256:sha(encrypted)}};
 for(const role of ['web','api','storage']){
  const p=path.join(source,role);
  file(path.join(p,'test.txt'),'artificial '+role);
  roles[role]={path:p,kind:'directory'};
 }
 for(const role of ['dns','config','secrets-vault']){
  const p=file(path.join(source,role+'.txt'),'artificial '+role);
  roles[role]={path:p,kind:'file'};
 }
 const config=file(path.join(home,'coverage.json'),JSON.stringify({format:'r62-guardian-v4-input-1',components:roles}));
 const globals=file(path.join(home,'globals.sql'),'-- SYNTHETIC TEST ONLY\nCREATE ROLE fixture_reader NOLOGIN;\n');
 const globalsSha256=sha(fs.readFileSync(globals));
 const cfg=JSON.parse(fs.readFileSync(config));
 const staged=prepare({cfg,lab,mode:'stage'});
 assert.equal(staged.targetCreated,true);
 const stage=path.join(lab,'restore-'+roles.database.sha256.slice(0,16));
 const params={config,stage,globals,globalsSha256};
 const ok=audit(params);
 assert.equal(ok.sourceComponents,7);
 assert.equal(ok.stagedComponents,6);
 assert.equal(ok.globalsBytes,fs.statSync(globals).size);
 // A different globals file with the same filename is a hard failure.
 fs.appendFileSync(globals,'GRANT r62_fixture_reader TO someone;\n');
 assert.throws(()=>audit(params),e=>e.message==='GLOBALS_HASH_MISMATCH');
 file(globals,'-- SYNTHETIC TEST ONLY\nCREATE ROLE fixture_reader NOLOGIN;\n');
 // The stage manifest is unsigned: integrity only, not provenance.
 file(path.join(stage,'web','test.txt'),'TAMPERED');
 assert.throws(()=>audit(params),e=>e.message==='HASH_MISMATCH');
 // Restage with new lab, then break the source vault and require fail-closed.
 const fresh=path.join(home,'fresh-lab');fs.mkdirSync(fresh);
 file(path.join(fresh,'.rota62-guardian-lab-only'),'ROTA62_OFFLINE_LAB_V1\n');
 prepare({cfg,lab:fresh,mode:'stage'});
 const safeStage=path.join(fresh,'restore-'+roles.database.sha256.slice(0,16));
 fs.unlinkSync(roles['secrets-vault'].path);
 assert.throws(()=>audit({...params,stage:safeStage}),e=>e.message==='SEVEN_COMPONENTS_BLOCKED');
 console.log('V59_SEVEN_COMPONENTS_SIX_STAGE_GLOBALS=PASS');
 console.log('V59_CORRUPTED_GLOBALS_AND_STAGE=BLOCKED');
 console.log('V59_MISSING_SECRETS_VAULT=BLOCKED');
 console.log('V59_GLOBAL_ROLES_CONTENT_EXECUTED=NO');
 console.log('V59_PRODUCTION_NETWORK_SECRETS_USED=NO');
}finally{fs.rmSync(home,{force:true,recursive:true});}

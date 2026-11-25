#!/usr/bin/env node
// All files are synthetic. No network, no real backups.
import {prepare} from './GuardianV5-LabStage.mjs';
import {verifyStage} from './GuardianV5-VerifyStage.mjs';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,existsSync,rmSync,readdirSync,statSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
const root=mkdtempSync(path.join(os.tmpdir(),'r62-v5-offline-'));
const base=path.join(root,'sources'),lab=path.join(root,'lab');
function data(components,role,kind,rel,content){
 const p=path.join(base,rel);
 if(kind==='directory'){mkdirSync(p,{recursive:true});writeFileSync(path.join(p,'fixture'),'synthetic-'+role);}
 else{mkdirSync(path.dirname(p),{recursive:true});writeFileSync(p,content);}
 components[role]={kind,path:p};
}
function blocked(fn,code){
 assert.throws(fn,e=>e.message===code,'expected error '+code);
}
try{
 mkdirSync(base);mkdirSync(lab);
 writeFileSync(path.join(lab,'.rota62-guardian-lab-only'),'ROTA62_OFFLINE_LAB_V1\n');
 const components={};
 data(components,'database','file','backup/snapshot.r62db','ENCRYPTED_SYNTHETIC_DATA_NO_SECRETS');
 data(components,'web','directory','web','');
 data(components,'api','directory','api','');
 data(components,'storage','directory','storage','');
 data(components,'dns','file','dns.json','SYNTHETIC');
 data(components,'config','file','config.json','SYNTHETIC_NONSECRET');
 data(components,'secrets-vault','file','vault.age','SYNTHETIC_OPAQUE_VAULT');
 components.database.sha256=crypto.createHash('sha256').update(readFileSync(components.database.path)).digest('hex');
 const cfg={format:'r62-guardian-v4-input-1',components};
 const name='restore-'+components.database.sha256.slice(0,16);
 const target=path.join(lab,name);
 const p=prepare({cfg,lab,mode:'plan'});
 assert.equal(p.targetCreated,false);
 assert.equal(existsSync(target),false);
 assert.equal(p.componentRoles,6);
 const s=prepare({cfg,lab,mode:'stage'});
 assert.equal(s.targetCreated,true);
 const manifest=JSON.parse(readFileSync(path.join(target,'manifest.json'),'utf8'));
 assert.equal(manifest.format,'r62-guardian-v5-lab-stage-1');
 assert.equal(manifest.secretsVaultIncluded,false);
 assert.equal(manifest.entries.length,6);
 assert.equal(verifyStage(target).files,6);
 assert.equal(existsSync(path.join(target,'secrets-vault')),false);
 assert.equal(readFileSync(path.join(target,'database','snapshot.r62db'),'utf8'),'ENCRYPTED_SYNTHETIC_DATA_NO_SECRETS');
 for(const entry of manifest.entries){
  const h=crypto.createHash('sha256').update(readFileSync(path.join(target,entry.name))).digest('hex');
  assert.equal(h,entry.sha256);
 }
 blocked(()=>prepare({cfg,lab,mode:'stage'}),'TARGET_EXISTS_NO_OVERWRITE');
 assert.equal(statSync(path.join(target,'manifest.json')).isFile(),true);
 // Verify stage without needing original sources, and detect copied artifact tampering.
 writeFileSync(path.join(target,'web','fixture'),'CORRUPTED');
 blocked(()=>verifyStage(target),'HASH_MISMATCH');
 writeFileSync(path.join(target,'web','fixture'),'synthetic-web');
 assert.equal(verifyStage(target).files,6);
 writeFileSync(path.join(target,'unexpected'),'EXTRA');
 blocked(()=>verifyStage(target),'EXTRA_OR_MISSING_FILE');
 rmSync(path.join(target,'unexpected'));
 assert.equal(verifyStage(target).files,6);
 writeFileSync(components.database.path,'TAMPER');
 blocked(()=>prepare({cfg,lab,mode:'plan'}),'SEVEN_COMPONENTS_NOT_VERIFIED');
 assert.equal(readdirSync(lab).filter(x=>x.startsWith('.r62-staging-')).length,0);
 writeFileSync(components.database.path,'ENCRYPTED_SYNTHETIC_DATA_NO_SECRETS');
 writeFileSync(path.join(lab,'.rota62-guardian-lab-only'),'BROKEN');
 blocked(()=>prepare({cfg,lab,mode:'plan'}),'LAB_MARKER_INVALID');
 console.log('V5_STAGE_COPY_SHA256_ATOMIC_NO_OVERWRITE_TAMPER_MARKER=PASS');
}finally{rmSync(root,{recursive:true,force:true});}

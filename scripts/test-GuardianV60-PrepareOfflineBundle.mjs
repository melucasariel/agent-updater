#!/usr/bin/env node
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import {prepareOfflineBundle} from './GuardianV60-PrepareOfflineBundle.mjs';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'r62-v60-prepare-'));
const lab=path.join(root,'lab'),src=path.join(root,'source');
fs.mkdirSync(lab);
fs.writeFileSync(path.join(lab,'.rota62-guardian-lab-only'),'ROTA62_OFFLINE_LAB_V1\n');
const file=(p,content)=>{fs.mkdirSync(path.dirname(p),{recursive:true});fs.writeFileSync(p,content);return p;};
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const roles=['database','web','api','storage','dns','config','globals','secrets-vault'];
const components={};
for(const role of roles){
 const content=Buffer.concat([Buffer.from(role==='database'?'R62DB02\n':'SYNTHETIC_NO_PRIVATE_DATA_'+role),Buffer.alloc(180,42)]);
 const p=file(path.join(src,role+'.bin'),content);
 components[role]={path:p,sha256:sha(content)};
}
const config=file(path.join(src,'snapshot-config.json'),JSON.stringify({
 format:'r62-guardian-v60-prepared-files-1',captureId:'v60-synthetic-20261125',
 release:'release-synthetic-1',components}));
try{
 const result=prepareOfflineBundle({configFile:config,labRoot:lab});
 assert.equal(result.componentsCopied,7);
 const bundle=path.join(lab,'backup-v60-synthetic-20261125');
 for(const role of roles.filter(x=>x!=='secrets-vault')){
  assert.equal(sha(fs.readFileSync(path.join(bundle,role,'snapshot.bin'))),components[role].sha256);
 }
 assert.equal(fs.existsSync(path.join(bundle,'secrets-vault')),false);
 assert.throws(()=>prepareOfflineBundle({configFile:config,labRoot:lab}),e=>e.message==='BUNDLE_ALREADY_EXISTS');
 const otherLab=path.join(root,'other-lab');fs.mkdirSync(otherLab);
 file(path.join(otherLab,'.rota62-guardian-lab-only'),'ROTA62_OFFLINE_LAB_V1\n');
 fs.appendFileSync(components.globals.path,'TAMPER');
 assert.throws(()=>prepareOfflineBundle({configFile:config,labRoot:otherLab}),e=>e.message==='SOURCE_HASH_MISMATCH');
 assert.equal(fs.readdirSync(otherLab).length,1);
 const missingLab=path.join(root,'missing-lab');fs.mkdirSync(missingLab);
 assert.throws(()=>prepareOfflineBundle({configFile:config,labRoot:missingLab}),
  e=>e.code==='ENOENT'||e.message==='LAB_MARKER_INVALID');
 console.log('V60_ATOMIC_SEVEN_COMPONENT_COPY=PASS');
 console.log('V60_SECRETS_VAULT_NEVER_COPIED=YES');
 console.log('V60_DUPLICATE_BACKUP_AND_TAMPER=BLOCKED');
 console.log('V60_NO_PRODUCTION_BACKUP_CAPTURE=YES');
}finally{fs.rmSync(root,{force:true,recursive:true});}

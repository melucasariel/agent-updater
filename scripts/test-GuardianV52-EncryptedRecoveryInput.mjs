#!/usr/bin/env node
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,copyFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {prepare} from './GuardianV5-LabStage.mjs';
import {review} from './GuardianV52-EncryptedRecoveryInput.mjs';
const root=mkdtempSync(path.join(tmpdir(),'r62-v52-ci-'));
function write(dir,name,data){
 mkdirSync(dir,{recursive:true});
 const p=path.join(dir,name);writeFileSync(p,data);return p;
}
try{
 const privateRoot=path.join(root,'private'),lab=path.join(root,'lab');
 mkdirSync(lab);
 writeFileSync(path.join(lab,'.rota62-guardian-lab-only'),'ROTA62_OFFLINE_LAB_V1\n');
 const encrypted=Buffer.concat([Buffer.from('R62DB02','ascii'),crypto.randomBytes(512)]);
 const archive=write(privateRoot,'snapshot.r62db',encrypted);
 const ref=crypto.createHash('sha256').update(encrypted).digest('hex');
 const copies=[write(path.join(privateRoot,'extra'),'copy1.r62db',encrypted),write(path.join(privateRoot,'extra'),'copy2.r62db',encrypted)];
 const parts={database:{kind:'file',path:archive,sha256:ref}};
 for(const role of ['web','api','storage']){
  const p=path.join(privateRoot,role);
  write(p,'synthetic.txt','synthetic '+role);
  parts[role]={kind:'directory',path:p};
 }
 for(const role of ['dns','config','secrets-vault']){
  const file=write(privateRoot,role+'.txt','safe synthetic '+role);
  parts[role]={kind:'file',path:file};
 }
 const cfg={format:'r62-guardian-v4-input-1',components:parts};
 const stage=prepare({cfg,lab,mode:'stage'});
 assert.equal(stage.targetCreated,true);
 const stageDir=path.join(lab,'restore-'+ref.slice(0,16));
 const input={'--archive':archive,'--reference-sha256':ref,'--copy-1':copies[0],'--copy-2':copies[1],'--stage':stageDir};
 const good=review(input);
 assert.equal(good.copies,3);
 assert.equal(good.uniqueSnapshots,1);
 assert.equal(good.stage.files,6);
 assert.equal(good.archive.size,encrypted.length);
 const changed=Buffer.from(encrypted);changed[20]^=1;
 writeFileSync(copies[0],changed);
 assert.throws(()=>review(input),e=>e.message==='COPY_HASH_MISMATCH');
 writeFileSync(copies[0],encrypted);
 const corrupt=Buffer.from(encrypted);corrupt[0]=0;
 writeFileSync(copies[0],corrupt);
 assert.throws(()=>review(input),e=>e.message==='UNEXPECTED_ARCHIVE_MAGIC');
 writeFileSync(copies[0],encrypted);
 assert.throws(()=>review({...input,'--reference-sha256':'0'.repeat(64)}),e=>e.message==='CIPHERTEXT_HASH_MISMATCH');
 writeFileSync(path.join(stageDir,'web','synthetic.txt'),'TAMPERED');
 assert.throws(()=>review(input),e=>e.message==='HASH_MISMATCH');
 console.log('V52_ENCRYPTED_INPUT_HASH_DUPLICATES_STAGE_TAMPER_GATES=PASS');
}finally{rmSync(root,{recursive:true,force:true});}

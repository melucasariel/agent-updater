#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {prepareOfflineBundle} from './GuardianV60-PrepareOfflineBundle.mjs';
import {signPreparedBundle} from './GuardianV60-SignPreparedBundle.mjs';
import {summarizeIndex} from './GuardianV61-SignedRecoveryInventory.mjs';

const root=fs.mkdtempSync(path.join(os.tmpdir(),'r62-v61-inventory-'));
const put=(f,b)=>{fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,b);return f;};
const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
const roles=['database','web','api','storage','dns','config','globals','secrets-vault'];
const kp=crypto.generateKeyPairSync('ed25519');
const password='SYNTHETIC_ONLY_SIGNING_PASS_2026';
const keyfile=put(path.join(root,'keys','encrypted.pem'),
 kp.privateKey.export({format:'pem',type:'pkcs8',cipher:'aes-256-cbc',passphrase:password}));
const publicKeyFile=put(path.join(root,'keys','public.pem'),
 kp.publicKey.export({format:'pem',type:'spki'}));
const keySha256=hash(kp.publicKey.export({format:'der',type:'spki'}));
const vaultFile=put(path.join(root,'vault','vault.enc'),Buffer.alloc(144,7));
const immutableDatabase=Buffer.concat([Buffer.from('R62DB02\n'),Buffer.alloc(170,51)]);
const entries=[];
function prepare(captureId,release,variant,labName){
 const lab=path.join(root,'lab-'+labName);
 fs.mkdirSync(lab);
 put(path.join(lab,'.rota62-guardian-lab-only'),'ROTA62_OFFLINE_LAB_V1\n');
 const source=path.join(root,'source-'+labName);
 const components={};
 for(const role of roles){
  let b;
  if(role==='secrets-vault')b=fs.readFileSync(vaultFile);
  else if(role==='database')b=immutableDatabase;
  else b=Buffer.concat([Buffer.from('TEST_'+role+(role==='web'?'_'+variant:'')),Buffer.alloc(132,17)]);
  const f=role==='secrets-vault'?vaultFile:put(path.join(source,role+'.bin'),b);
  components[role]={path:f,sha256:hash(b)};
 }
 const configFile=put(path.join(source,'prepared.json'),
  JSON.stringify({format:'r62-guardian-v60-prepared-files-1',captureId,release,components}));
 prepareOfflineBundle({configFile,labRoot:lab});
 const bundleRoot=path.join(lab,'backup-'+captureId);
 signPreparedBundle({bundleRoot,vaultFile,privateKeyFile:keyfile,publicKeyFile,
  captureId,release,createdUtc:'2026-11-25T00:00:00.000Z',passphrase:password});
 const entry={bundleRoot,vaultFile,publicKeyFile,keySha256};
 entries.push(entry);return entry;
}
const index=path.join(root,'inventory.json');
const save=()=>put(index,JSON.stringify({format:'r62-guardian-v61-inventory-1',entries}));
try{
 prepare('20261125-fixture-a','release-version-A','same','A');
 prepare('20261125-fixture-a-copy','release-version-A','same','B');
 prepare('20261125-fixture-b','release-version-B','new-web-only','C');
 save();
 const s=summarizeIndex(index);
 assert.equal(s.signedBundles,3);
 assert.equal(s.distinctPackages,2);
 assert.equal(s.distinctEncryptedArchives,1);
 assert.equal(s.identicalPackageCopies,1);
 assert.equal(s.releaseLabels,2);
 assert.equal(s.trustedSignerKeys,1);
 entries.push({...entries[0]});
 save();
 assert.throws(()=>summarizeIndex(index),e=>e.message==='INDEX_DUPLICATE_BUNDLE');
 entries.pop();
 const oldKey=entries[2].keySha256;
 entries[2].keySha256='0'.repeat(64);
 save();
 assert.throws(()=>summarizeIndex(index),/TRUST_KEY_FINGERPRINT_MISMATCH/);
 entries[2].keySha256=oldKey;
 save();
 // A previously signed bundle with same captureId but different content
 // must not be accepted as the original historical capture.
 prepare('20261125-fixture-a','release-version-X','different','D');
 save();
 assert.throws(()=>summarizeIndex(index),e=>e.message==='CAPTURE_ID_COLLISION');
 console.log('V61_SIGNED_BACKUP_HISTORY_THREE_COPIES_ONE_DB_POINT=PASS');
 console.log('V61_RELEASE_VERSIONS_DISTINCT_FROM_DB_POINTS=PASS');
 console.log('V61_CAPTURE_COLLISION_AND_KEY_SUBSTITUTION=BLOCKED');
 console.log('V61_NO_PASSWORD_OR_PRODUCTION_SECRETS_USED=YES');
}finally{fs.rmSync(root,{force:true,recursive:true});}

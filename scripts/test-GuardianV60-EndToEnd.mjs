#!/usr/bin/env node
// Integrated V6.0: prepare -> sign -> verify -> reject tampered signed archive.
import fs from 'node:fs';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import {prepareOfflineBundle} from './GuardianV60-PrepareOfflineBundle.mjs';
import {signPreparedBundle} from './GuardianV60-SignPreparedBundle.mjs';
import {checkSignedBundle} from './GuardianV60-SignedBundleTrust.mjs';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'r62-v60-end-to-end-'));
const files=path.join(root,'source'),lab=path.join(root,'lab'),outside=path.join(root,'trust');
const sha=b=>crypto.createHash('sha256').update(b).digest('hex');
const put=(f,b)=>{fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,b);return f};
const roles=['database','web','api','storage','dns','config','globals','secrets-vault'];
const components={};
try{
 fs.mkdirSync(lab);
 put(path.join(lab,'.rota62-guardian-lab-only'),'ROTA62_OFFLINE_LAB_V1\n');
 for(const role of roles){
  const b=Buffer.concat([Buffer.from(role==='database'?'R62DB02\n':'FAKE_V60_ONLY_'+role),Buffer.alloc(128,7)]);
  components[role]={path:put(path.join(files,role+'.bin'),b),sha256:sha(b)};
 }
 const captureId='v60-entire-synthetic',release='test-release-v60';
 const config=put(path.join(files,'prepared.json'),JSON.stringify({
  format:'r62-guardian-v60-prepared-files-1',captureId,release,components}));
 const staged=prepareOfflineBundle({configFile:config,labRoot:lab});
 assert.equal(staged.componentsCopied,7);
 const bundle=path.join(lab,'backup-'+captureId);
 const kp=crypto.generateKeyPairSync('ed25519'),password='fake-only-ci-passphrase';
 const privateKey=put(path.join(outside,'private-encrypted.pem'),
  kp.privateKey.export({type:'pkcs8',format:'pem',cipher:'aes-256-cbc',passphrase:password}));
 const publicKey=put(path.join(outside,'public-trusted.pem'),
  kp.publicKey.export({type:'spki',format:'pem'}));
 const expectedKeySha256=sha(kp.publicKey.export({type:'spki',format:'der'}));
 const vault=components['secrets-vault'].path;
 signPreparedBundle({bundleRoot:bundle,vaultFile:vault,privateKeyFile:privateKey,
  publicKeyFile:publicKey,passphrase:password,captureId,release,
  createdUtc:'2026-11-25T00:00:00.000Z'});
 const verify=()=>checkSignedBundle({bundleRoot:bundle,manifestFile:path.join(bundle,'manifest.json'),
  signatureFile:path.join(bundle,'manifest.sig'),publicKeyFile:publicKey,vaultFile:vault,expectedKeySha256});
 assert.equal(verify().count,8);
 // Changing a source snapshot after atomic copy cannot silently alter a signed bundle.
 fs.appendFileSync(components.web.path,'CHANGED_AFTER_COPY');
 assert.equal(verify().count,8);
 // Changing the signed archive copy IS detected.
 fs.appendFileSync(path.join(bundle,'web','snapshot.bin'),'TAMPERED_AFTER_SIGNING');
 assert.throws(verify,e=>e.message==='COMPONENT_HASH_MISMATCH');
 console.log('V60_PREPARE_SIGN_VERIFY_INTEGRATED=PASS');
 console.log('V60_SOURCE_AFTER_COPY_INDEPENDENCE=PASS');
 console.log('V60_TAMPERED_SIGNED_BUNDLE_FAIL_CLOSED=PASS');
 console.log('V60_PRODUCTION_DATA_USED=NO');
}finally{fs.rmSync(root,{recursive:true,force:true});}

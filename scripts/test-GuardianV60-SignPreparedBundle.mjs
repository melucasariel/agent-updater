#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {signPreparedBundle} from './GuardianV60-SignPreparedBundle.mjs';
import {checkSignedBundle} from './GuardianV60-SignedBundleTrust.mjs';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'r62-v60-signer-'));
const bundle=path.join(root,'bundle'),privateDir=path.join(root,'private');
const put=(file,data)=>{fs.mkdirSync(path.dirname(file),{recursive:true});fs.writeFileSync(file,data);return file;};
const roles=['database','web','api','storage','dns','config','globals'];
const password='ONLY_SYNTHETIC_SIGNING_KEY_CI';
const pair=crypto.generateKeyPairSync('ed25519');
const encryptedKey=put(path.join(privateDir,'encrypted-private.pem'),
 pair.privateKey.export({format:'pem',type:'pkcs8',cipher:'aes-256-cbc',passphrase:password}));
const publicKey=put(path.join(privateDir,'public.pem'),pair.publicKey.export({format:'pem',type:'spki'}));
const externalVault=put(path.join(privateDir,'vault.enc'),'SYNTHETIC_ONLY_ENCRYPTED_VAULT_PLACEHOLDER');
for(const role of roles)put(path.join(bundle,role,'snapshot.bin'),'SYNTHETIC_'+role+'_DATA');
const args={bundleRoot:bundle,privateKeyFile:encryptedKey,publicKeyFile:publicKey,
 vaultFile:externalVault,captureId:'20261125-CI-SNAPSHOT',release:'release-CI-fixture',
 createdUtc:'2026-11-25T00:00:00.000Z',passphrase:password};
try{
 assert.throws(()=>signPreparedBundle({...args,passphrase:'WRONG_PASSWORD'}),
  e=>e.message==='PRIVATE_KEY_DECRYPT_FAILED');
 assert.equal(fs.existsSync(path.join(bundle,'manifest.json')),false);
 const okay=signPreparedBundle(args);
 assert.equal(okay.count,8);
 assert.equal(fs.statSync(path.join(bundle,'manifest.sig')).size,64);
 assert.equal(checkSignedBundle({bundleRoot:bundle,manifestFile:path.join(bundle,'manifest.json'),
  signatureFile:path.join(bundle,'manifest.sig'),publicKeyFile:publicKey,vaultFile:externalVault}).count,8);
 assert.throws(()=>signPreparedBundle(args),e=>e.message==='NO_OVERWRITE');
 // Even if the signing key is valid, a changed artifact must be rejected.
 fs.appendFileSync(path.join(bundle,'web','snapshot.bin'),'TAMPERED');
 assert.throws(()=>checkSignedBundle({bundleRoot:bundle,manifestFile:path.join(bundle,'manifest.json'),
  signatureFile:path.join(bundle,'manifest.sig'),publicKeyFile:publicKey,vaultFile:externalVault}),
  e=>e.message==='COMPONENT_HASH_MISMATCH');
 console.log('V60_MANUAL_SIGNER_ENCRYPTED_PRIVATE_KEY=PASS');
 console.log('V60_SIGNING_PASSWORD_WRONG_OR_REUSED=BLOCKED');
 console.log('V60_SIGNATURE_VS_TAMPERED_ARTIFACT=BLOCKED');
 console.log('V60_PRIVATE_KEY_OUTSIDE_BUNDLE=YES');
 console.log('V60_REAL_BACKUP_OR_SECRET_USED=NO');
}finally{fs.rmSync(root,{recursive:true,force:true});}

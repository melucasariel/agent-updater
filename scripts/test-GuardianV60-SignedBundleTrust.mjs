#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {checkSignedBundle} from './GuardianV60-SignedBundleTrust.mjs';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'r62-v60-trust-'));
const bundle=path.join(root,'bundle'),privateDir=path.join(root,'private');
const roles=['database','web','api','storage','dns','config','globals','secrets-vault'];
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const put=(f,b)=>{fs.mkdirSync(path.dirname(f),{recursive:true});fs.writeFileSync(f,b);return f};
const keys=crypto.generateKeyPairSync('ed25519');
const priv=put(path.join(privateDir,'ed25519-private.pem'),keys.privateKey.export({type:'pkcs8',format:'pem'}));
const pub=put(path.join(privateDir,'trusted-public.pem'),keys.publicKey.export({type:'spki',format:'pem'}));
const foreign=crypto.generateKeyPairSync('ed25519').publicKey.export({type:'spki',format:'pem'});
const otherPub=put(path.join(privateDir,'wrong-public.pem'),foreign);
const mf=path.join(bundle,'manifest.json'),sig=path.join(bundle,'manifest.sig');
const vault=put(path.join(privateDir,'external-vault.enc'),Buffer.from('ENCRYPTED_SYNTHETIC_ONLY_VAULT'));
function build(){
 const entries=[];
 for(const role of roles){
  const name=role==='secrets-vault'?'EXTERNAL_VAULT':role+'/snapshot.bin';
  const file=role==='secrets-vault'?vault:put(path.join(bundle,...name.split('/')),Buffer.from('SYNTHETIC_BINARY_CONTENT_'+role));
  const bytes=fs.readFileSync(file);
  entries.push({role,file:name,bytes:bytes.length,sha256:sha(bytes)});
 }
 const m={format:'r62-guardian-v6-signed-1',captureId:'fixture-20261125-A',createdUtc:'2026-11-25T00:00:00.000Z',release:'test-release-1',components:entries};
 put(mf,Buffer.from(JSON.stringify(m)));
 put(sig,crypto.sign(null,fs.readFileSync(mf),keys.privateKey));
 return m;
}
const expectedKeySha256=sha(keys.publicKey.export({format:'der',type:'spki'}));
const params={bundleRoot:bundle,manifestFile:mf,signatureFile:sig,publicKeyFile:pub,vaultFile:vault,expectedKeySha256};
const denied=(change,code)=>{
 assert.throws(()=>checkSignedBundle(change),e=>e.message===code,'Expected '+code);
};
try{
 const manifest=build();
 let result=checkSignedBundle(params);
 assert.equal(result.count,8);
 assert.ok(result.totalBytes>50);
 denied({...params,publicKeyFile:otherPub},'TRUST_KEY_FINGERPRINT_MISMATCH');
 denied({...params,expectedKeySha256:'0'.repeat(64)},'TRUST_KEY_FINGERPRINT_MISMATCH');
 // Signature authenticates the exact manifest bytes, not just parsed fields.
 fs.appendFileSync(mf,' ');
 denied(params,'SIGNATURE_INVALID');
 build();
 const snapshot=path.join(bundle,'web','snapshot.bin');
 fs.appendFileSync(snapshot,'TAMPER');
 denied(params,'COMPONENT_HASH_MISMATCH');
 build();
 fs.appendFileSync(vault,'TAMPER');
 denied(params,'COMPONENT_HASH_MISMATCH');
 put(vault,Buffer.from('ENCRYPTED_SYNTHETIC_ONLY_VAULT'));
 build();
 // Re-signing a forged manifest is possible with the test key, but a trusted
 // signer does not make an unverified restore semantically safe.
 const m=JSON.parse(fs.readFileSync(mf));
 m.components[0].file='../escape';
 put(mf,JSON.stringify(m));put(sig,crypto.sign(null,fs.readFileSync(mf),keys.privateKey));
 denied(params,'INVALID_COMPONENT');
 build();
 const unexpected=put(path.join(bundle,'undeclared-secret.key'),'SYNTHETIC_ONLY');
 denied(params,'UNDECLARED_BUNDLE_FILE');
 fs.rmSync(unexpected);
 const insidePub=put(path.join(bundle,'trusted.pem'),fs.readFileSync(pub));
 denied({...params,publicKeyFile:insidePub},'TRUST_ANCHOR_INSIDE_BUNDLE');
 // No symlink from within bundle to a file outside, even with a valid
 // signature over exactly the same serialized metadata.
 if(process.platform!=='win32'){
  build();
  const target=path.join(bundle,'api','snapshot.bin');
  fs.rmSync(target);fs.symlinkSync(vault,target);
  denied(params,'UNSAFE_FILE');
 }
 console.log('V60_ED25519_SEPARATE_TRUST_ANCHOR=PASS');
 console.log('V60_EIGHT_COMPONENTS_SEVEN_BUNDLE_ONE_EXTERNAL_VAULT=PASS');
 console.log('V60_CHANGED_MANIFEST_WRONG_KEY_CHANGED_ARTIFACTS=BLOCKED');
 console.log('V60_SOURCE_CONTENT_NEVER_EXECUTED=YES');
 console.log('V60_PRODUCTION_SECRETS_USED=NO');
}finally{fs.rmSync(root,{recursive:true,force:true});}

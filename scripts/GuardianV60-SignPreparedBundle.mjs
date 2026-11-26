#!/usr/bin/env node
// Guardian V6.0 — explicit MANUAL signing of an already-prepared offline bundle.
// Private key MUST be encrypted PKCS#8 and stored OUTSIDE the backup bundle.
// No data collection, Docker, SQL, uploads, updates or production operations.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {checkSignedBundle} from './GuardianV60-SignedBundleTrust.mjs';
const ROLES=['database','web','api','storage','dns','config','globals'];
const fail=s=>{throw Error(s)};
const id=/^[a-zA-Z0-9][a-zA-Z0-9._-]{7,99}$/;
function safePath(filename){
 if(typeof filename!=='string'||!path.isAbsolute(filename))fail('INVALID_PATH');
 const s=fs.lstatSync(filename);
 if(!s.isFile()||s.isSymbolicLink()||s.size<1||s.size>10*1024**3)fail('INVALID_FILE');
 return s;
}
function digest(filename){
 const h=crypto.createHash('sha256');
 const fd=fs.openSync(filename,'r');
 try{
  const b=Buffer.allocUnsafe(1024*1024);
  while(true){const n=fs.readSync(fd,b,0,b.length,null);if(!n)break;h.update(b.subarray(0,n));}
 }finally{fs.closeSync(fd);}
 return h.digest('hex');
}
function under(root,other){
 const rel=path.relative(root,other);
 return rel!==''&&!rel.startsWith('..'+path.sep)&&rel!=='..'&&!path.isAbsolute(rel);
}
export function signPreparedBundle({bundleRoot,vaultFile,privateKeyFile,publicKeyFile,passphrase,captureId,release,createdUtc}){
 if(!path.isAbsolute(bundleRoot)||!id.test(captureId||'')||!id.test(release||'')||
  typeof passphrase!=='string'||passphrase.length<1)fail('INVALID_ARGUMENTS');
 const stat=fs.lstatSync(bundleRoot);
 if(!stat.isDirectory()||stat.isSymbolicLink()||fs.realpathSync(bundleRoot)!==path.resolve(bundleRoot))fail('INVALID_BUNDLE');
 const root=fs.realpathSync(bundleRoot);
 for(const filename of [vaultFile,privateKeyFile,publicKeyFile]){
  safePath(filename);
  if(under(root,fs.realpathSync(filename)))fail('PRIVATE_OR_VAULT_INSIDE_BUNDLE');
 }
 const manifestFile=path.join(root,'manifest.json'),signatureFile=path.join(root,'manifest.sig');
 if(fs.existsSync(manifestFile)||fs.existsSync(signatureFile))fail('NO_OVERWRITE');
 const components=[];
 for(const role of ROLES){
  const file=path.join(root,role,'snapshot.bin');
  const s=safePath(file);
  if(!under(root,fs.realpathSync(file)))fail('BUNDLE_ESCAPE');
  components.push({role,file:role+'/snapshot.bin',bytes:s.size,sha256:digest(file)});
 }
 const vault=safePath(vaultFile);
 components.push({role:'secrets-vault',file:'EXTERNAL_VAULT',bytes:vault.size,sha256:digest(vaultFile)});
 const pem=fs.readFileSync(privateKeyFile,'utf8');
 if(!pem.includes('BEGIN ENCRYPTED PRIVATE KEY'))fail('PRIVATE_KEY_NOT_ENCRYPTED');
 let privateKey;try{privateKey=crypto.createPrivateKey({key:pem,passphrase});}catch{fail('PRIVATE_KEY_DECRYPT_FAILED');}
 if(privateKey.asymmetricKeyType!=='ed25519')fail('PRIVATE_KEY_NOT_ED25519');
 const anchored=crypto.createPublicKey(fs.readFileSync(publicKeyFile));
 if(anchored.asymmetricKeyType!=='ed25519'||
  !crypto.createPublicKey(privateKey).export({format:'der',type:'spki'}).equals(
    anchored.export({format:'der',type:'spki'})))fail('SIGNER_NOT_TRUSTED_KEY');
 const timestamp=createdUtc??new Date().toISOString();
 if(typeof timestamp!=='string'||new Date(timestamp).toISOString()!==timestamp)fail('INVALID_DATE');
 const manifest={format:'r62-guardian-v6-signed-1',captureId,createdUtc:timestamp,release,components};
 const raw=Buffer.from(JSON.stringify(manifest)+'\n','utf8');
 const signature=crypto.sign(null,raw,privateKey);
 let wroteManifest=false,wroteSignature=false;
 try{
  fs.writeFileSync(manifestFile,raw,{flag:'wx',mode:0o600});wroteManifest=true;
  fs.writeFileSync(signatureFile,signature,{flag:'wx',mode:0o600});wroteSignature=true;
  const trustedFingerprint=crypto.createHash('sha256').update(anchored.export({type:'spki',format:'der'})).digest('hex');
  const result=checkSignedBundle({bundleRoot:root,manifestFile,signatureFile,publicKeyFile,vaultFile,expectedKeySha256:trustedFingerprint});
  return result;
 }catch(e){
  // Delete only files created by this call, never preexisting backups or keys.
  if(wroteSignature)try{fs.rmSync(signatureFile)}catch{}
  if(wroteManifest)try{fs.rmSync(manifestFile)}catch{}
  throw e;
 }
}
async function readPassphrase(){
 if(!process.stdin.isTTY||!process.stdin.setRawMode)fail('TTY_REQUIRED');
 return new Promise((resolve,reject)=>{
  let val='',ended=false;
  const old=process.stdin.isRaw;
  function finish(e){
   if(ended)return;ended=true;process.stdin.off('data',read);
   process.stdin.setRawMode(Boolean(old));process.stdin.pause();process.stdout.write('\n');
   e?reject(e):resolve(val);
  }
  function read(b){
   for(const c of b.toString('utf8')){
    if(c==='\x03'){finish(Error('CANCELLED'));return;}
    if(c==='\r'||c==='\n'){finish();return;}
    if(c==='\b'||c==='\x7f'){if(val.length){val=val.slice(0,-1);process.stdout.write('\b \b');}continue;}
    if(c>=' '&&val.length<1024){val+=c;process.stdout.write('*');}
   }
  }
  process.stdout.write('Senha da CHAVE DE ASSINATURA (somente local): ');
  process.stdin.setRawMode(true);process.stdin.resume();process.stdin.on('data',read);
 });
}
async function cli(a){
 const keys=['--bundle-root','--external-vault','--encrypted-private-key','--trusted-public-key','--capture-id','--release'];
 if(a.length!==12)fail('USAGE');
 const m={};
 for(let i=0;i<12;i+=2){if(!keys.includes(a[i])||Object.hasOwn(m,a[i]))fail('USAGE');m[a[i]]=a[i+1];}
 if(Object.keys(m).length!==6)fail('USAGE');
 const password=await readPassphrase();
 const result=signPreparedBundle({bundleRoot:m['--bundle-root'],vaultFile:m['--external-vault'],
  privateKeyFile:m['--encrypted-private-key'],publicKeyFile:m['--trusted-public-key'],
  captureId:m['--capture-id'],release:m['--release'],passphrase:password});
 console.log(['=== ROTA62 GUARDIAN V6.0 MANUAL SIGNATURE ===',
  'MANIFEST_AND_DETACHED_SIGNATURE_CREATED=YES','INDEPENDENT_TRUST_KEY_MATCH=YES',
  'SIGNED_COMPONENTS=8','COMPONENT_BYTES_VERIFIED='+result.totalBytes,
  'TRUSTED_KEY_SHA16='+result.keySha16,
  'PRODUCTION_TOUCHED=NO','BACKUP_CAPTURED_FROM_LIVE_SYSTEM=NO',
  'RECOVERY_READY=NO','END_REPORT_OK'].join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 cli(process.argv.slice(2)).catch(e=>{
  const safe=new Set(['USAGE','INVALID_PATH','INVALID_FILE','INVALID_BUNDLE',
   'INVALID_ARGUMENTS','PRIVATE_OR_VAULT_INSIDE_BUNDLE','NO_OVERWRITE',
   'BUNDLE_ESCAPE','PRIVATE_KEY_NOT_ENCRYPTED','PRIVATE_KEY_DECRYPT_FAILED',
   'PRIVATE_KEY_NOT_ED25519','SIGNER_NOT_TRUSTED_KEY','INVALID_DATE','TTY_REQUIRED','CANCELLED']);
  console.log('=== ROTA62 GUARDIAN V6.0 MANUAL SIGNATURE ===\nSTATUS=BLOCKED_'+
    (safe.has(e.message)?e.message:'REDACTED')+'\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 });
}

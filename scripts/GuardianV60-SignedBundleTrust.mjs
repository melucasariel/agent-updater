#!/usr/bin/env node
/**
 * Guardian V6.0 — independently signed recovery-bundle integrity gate.
 * Does NOT capture, decrypt, unpack, restore, deploy, or execute any input.
 * Detached Ed25519 signature, pinned trust key external to bundle,
 * exact byte hashes for 7 bundle artifacts + separate external vault.
 * An authenticated manifest is NOT proof of semantic completeness.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const fail=code=>{throw Error(code);};
const REQUIRED=['database','web','api','storage','dns','config','globals','secrets-vault'];
const MAX_MANIFEST=65536, MAX_ARTIFACT=10*1024**3;
const HASH=/^[a-f0-9]{64}$/;
const NAME=/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$/;
const ID=/^[a-zA-Z0-9][a-zA-Z0-9._-]{7,99}$/;
const KEYS=['format','captureId','createdUtc','release','components'];
const CK=['role','file','bytes','sha256'];
function checkKeys(value,keys){
 if(!value||typeof value!=='object'||Array.isArray(value)||
  Object.keys(value).sort().join('|')!==[...keys].sort().join('|'))fail('INVALID_MANIFEST_SCHEMA');
}
function safeFile(file,max){
 if(typeof file!=='string'||!path.isAbsolute(file))fail('UNSAFE_FILE_PATH');
 const stat=fs.lstatSync(file);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<1||stat.size>max)fail('UNSAFE_FILE');
 return {file,stat,real:fs.realpathSync(file)};
}
function under(root,file){
 const rel=path.relative(root,file);
 return rel!==''&&rel!=='..'&&!rel.startsWith('..'+path.sep)&&!path.isAbsolute(rel);
}
function bufferHash(file){
 const h=crypto.createHash('sha256');
 const fd=fs.openSync(file,'r');
 try{
  const buf=Buffer.allocUnsafe(1024*1024);
  for(;;){
   const n=fs.readSync(fd,buf,0,buf.length,null);
   if(!n)break;
   h.update(buf.subarray(0,n));
  }
 }finally{fs.closeSync(fd);}
 return h.digest('hex');
}
function checkPath(root,relative){
 if(typeof relative!=='string'||relative.length>280||relative.includes('\\')||
  relative.includes('\0')||relative.startsWith('/')||
  !relative.split('/').every(x=>NAME.test(x)&&x!=='.'&&x!=='..'))fail('INVALID_BUNDLE_PATH');
 const candidate=path.resolve(root,...relative.split('/'));
 if(!under(root,candidate))fail('INVALID_BUNDLE_PATH');
 const f=safeFile(candidate,MAX_ARTIFACT);
 if(!under(root,f.real))fail('SYMLINK_OR_ESCAPE_BLOCKED');
 return f;
}
export function checkSignedBundle({bundleRoot,manifestFile,signatureFile,publicKeyFile,vaultFile}){
 for(const item of [bundleRoot,manifestFile,signatureFile,publicKeyFile,vaultFile]){
  if(typeof item!=='string'||!path.isAbsolute(item))fail('INVALID_ARGUMENTS');
 }
 const rst=fs.lstatSync(bundleRoot);
 if(!rst.isDirectory()||rst.isSymbolicLink()||fs.realpathSync(bundleRoot)!==path.resolve(bundleRoot))fail('UNSAFE_BUNDLE_ROOT');
 const root=fs.realpathSync(bundleRoot);
 const pub=safeFile(publicKeyFile,8192);
 if(under(root,pub.real)||pub.real===root)fail('TRUST_ANCHOR_INSIDE_BUNDLE');
 const vault=safeFile(vaultFile,MAX_ARTIFACT);
 if(under(root,vault.real)||vault.real===root)fail('VAULT_INSIDE_BUNDLE');
 const mf=safeFile(manifestFile,MAX_MANIFEST),sig=safeFile(signatureFile,1024);
 if(!under(root,mf.real)||!under(root,sig.real)||mf.real===sig.real)fail('MANIFEST_NOT_IN_BUNDLE');
 const raw=fs.readFileSync(manifestFile);
 let m;try{m=JSON.parse(raw.toString('utf8'));}catch{fail('INVALID_MANIFEST_JSON');}
 checkKeys(m,KEYS);
 if(m.format!=='r62-guardian-v6-signed-1'||!ID.test(m.captureId)||!ID.test(m.release)||
  typeof m.createdUtc!=='string'||!Number.isFinite(Date.parse(m.createdUtc))||
  new Date(m.createdUtc).toISOString()!==m.createdUtc||
  !Array.isArray(m.components)||m.components.length!==REQUIRED.length)fail('INVALID_MANIFEST_SCHEMA');
 let key;
 try{key=crypto.createPublicKey(fs.readFileSync(pub.file));}catch{fail('INVALID_TRUST_ANCHOR');}
 if(key.asymmetricKeyType!=='ed25519')fail('TRUST_KEY_NOT_ED25519');
 const signature=fs.readFileSync(sig.file);
 if(signature.length!==64||!crypto.verify(null,raw,key,signature))fail('SIGNATURE_INVALID');
 const seenRoles=new Set(),seenFiles=new Set();
 let bytes=0;
 for(const entry of m.components){
  checkKeys(entry,CK);
  if(!REQUIRED.includes(entry.role)||seenRoles.has(entry.role)||!HASH.test(entry.sha256)||
    !Number.isSafeInteger(entry.bytes)||entry.bytes<1||entry.bytes>MAX_ARTIFACT)fail('INVALID_COMPONENT');
  seenRoles.add(entry.role);
  let artifact;
  if(entry.role==='secrets-vault'){
   if(entry.file!=='EXTERNAL_VAULT')fail('INVALID_COMPONENT');
   artifact=vault;
  }else{
   if(!entry.file.startsWith(entry.role+'/'))fail('INVALID_COMPONENT');
   artifact=checkPath(root,entry.file);
   if(seenFiles.has(artifact.real)||artifact.real===mf.real||artifact.real===sig.real)fail('DUPLICATE_COMPONENT_PATH');
   seenFiles.add(artifact.real);
  }
  if(artifact.stat.size!==entry.bytes||bufferHash(artifact.file)!==entry.sha256)fail('COMPONENT_HASH_MISMATCH');
  bytes+=entry.bytes;
 }
 if(seenRoles.size!==REQUIRED.length)fail('MISSING_COMPONENT');
 // Ensure signed manifest was not replaced between signature check and return.
 if(!crypto.verify(null,fs.readFileSync(manifestFile),key,signature))fail('MANIFEST_CHANGED');
 const fingerprint=crypto.createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex');
 return {count:seenRoles.size,totalBytes:bytes,keySha16:fingerprint.slice(0,16).toUpperCase(),
  manifestSha16:crypto.createHash('sha256').update(raw).digest('hex').slice(0,16).toUpperCase()};
}
function cli(argv){
 if(argv.length!==10)fail('USAGE');
 const keys=['--bundle-root','--manifest','--signature','--trusted-public-key','--external-vault'];
 const opts={};
 for(let i=0;i<10;i+=2){
  if(!keys.includes(argv[i])||Object.hasOwn(opts,argv[i]))fail('USAGE');
  opts[argv[i]]=argv[i+1];
 }
 if(Object.keys(opts).length!==5)fail('USAGE');
 const value=checkSignedBundle({
  bundleRoot:opts['--bundle-root'],manifestFile:opts['--manifest'],
  signatureFile:opts['--signature'],publicKeyFile:opts['--trusted-public-key'],
  vaultFile:opts['--external-vault']
 });
 console.log(['=== ROTA62 GUARDIAN V6.0 SIGNED BACKUP TRUST ===',
  'DETACHED_ED25519_SIGNATURE=PASS','TRUST_ANCHOR_EXTERNAL=YES',
  'EIGHT_REQUIRED_COMPONENTS=PASS','BUNDLE_COMPONENTS=7',
  'SECRETS_VAULT_EXTERNAL=YES','TOTAL_VERIFIED_BYTES='+value.totalBytes,
  'TRUSTED_KEY_SHA16='+value.keySha16,'MANIFEST_SHA16='+value.manifestSha16,
  'MANIFEST_ORIGIN_IMPLIED_BY_TRUSTED_KEY=YES',
  'CAPTURE_CONSISTENCY_TESTED=NO','GLOBALS_ROLE_SEMANTICS_TESTED=NO',
  'APPLICATION_RECOVERY_TESTED=NO','DATABASE_RESTORED=NO',
  'PRODUCTION_TOUCHED=NO','READY_TO_RECOVER=NO','END_REPORT_OK'].join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{cli(process.argv.slice(2));}
 catch(e){
  const known=new Set(['USAGE','INVALID_ARGUMENTS','INVALID_MANIFEST_SCHEMA','INVALID_MANIFEST_JSON',
    'UNSAFE_FILE','UNSAFE_FILE_PATH','UNSAFE_BUNDLE_ROOT','INVALID_BUNDLE_PATH',
    'TRUST_ANCHOR_INSIDE_BUNDLE','VAULT_INSIDE_BUNDLE','MANIFEST_NOT_IN_BUNDLE',
    'SYMLINK_OR_ESCAPE_BLOCKED','INVALID_TRUST_ANCHOR','TRUST_KEY_NOT_ED25519',
    'SIGNATURE_INVALID','INVALID_COMPONENT','DUPLICATE_COMPONENT_PATH',
    'COMPONENT_HASH_MISMATCH','MISSING_COMPONENT','MANIFEST_CHANGED']);
  console.log('=== ROTA62 GUARDIAN V6.0 SIGNED BACKUP TRUST ===\nSTATUS=BLOCKED_'+
   (known.has(e.message)?e.message:'REDACTED')+
   '\nDATABASE_RESTORED=NO\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

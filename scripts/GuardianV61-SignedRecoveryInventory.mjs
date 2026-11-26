#!/usr/bin/env node
/**
 * ROTA62 Guardian V6.1 - VERIFIED signed backup inventory.
 *
 * Read-only list of pre-existing signed backup sets. Differentiates
 * (1) packages with verified signatures, (2) distinct database recovery
 * points, and (3) release labels. Never asserts original live provenance.
 *
 * Input index JSON references local, absolute bundle paths and separate
 * vaults. It is NOT trusted; each bundle is authenticated with pinned
 * Ed25519 public-key SHA256 and per-artifact SHA256 before counting.
 * No databases, network, Docker, SQL, private keys or passwords involved.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {checkSignedBundle} from './GuardianV60-SignedBundleTrust.mjs';

const fail=c=>{throw Error(c);};
const key=/^[a-f0-9]{64}$/i;
function exact(obj,props){
 if(!obj||typeof obj!=='object'||Array.isArray(obj)||
   Object.keys(obj).sort().join(',')!==[...props].sort().join(','))fail('INDEX_SCHEMA_INVALID');
}
function canonicalId(m){
 // This ID is computed from verified byte hashes, NOT filenames.
 const roles=['database','web','api','storage','dns','config','globals','secrets-vault'];
 const index=new Map(m.components.map(x=>[x.role,x]));
 const stable=roles.map(role=>{
  const o=index.get(role);
  if(!o||typeof o.sha256!=='string'||!key.test(o.sha256))fail('MANIFEST_COMPONENT_INVALID');
  return role+':'+o.sha256.toLowerCase();
 }).join('\n');
 return crypto.createHash('sha256').update(stable,'utf8').digest('hex');
}
export function summarizeIndex(indexFile){
 if(!path.isAbsolute(indexFile))fail('INDEX_PATH_INVALID');
 const st=fs.lstatSync(indexFile);
 if(!st.isFile()||st.isSymbolicLink()||st.size<3||st.size>1024*1024)fail('INDEX_INVALID');
 let index;try{index=JSON.parse(fs.readFileSync(indexFile,'utf8'));}catch{fail('INDEX_JSON_INVALID');}
 exact(index,['format','entries']);
 if(index.format!=='r62-guardian-v61-inventory-1'||!Array.isArray(index.entries)||
    index.entries.length<1||index.entries.length>250)fail('INDEX_SCHEMA_INVALID');
 const captureIds=new Map(),bundlePaths=new Set();
 const dbSnapshots=new Map(),packages=new Map(),releases=new Set(),keys=new Set();
 let identicalCopies=0;
 for(const entry of index.entries){
  exact(entry,['bundleRoot','vaultFile','publicKeyFile','keySha256']);
  for(const f of [entry.bundleRoot,entry.vaultFile,entry.publicKeyFile])if(typeof f!=='string'||!path.isAbsolute(f))fail('INDEX_PATH_INVALID');
  if(typeof entry.keySha256!=='string'||!key.test(entry.keySha256))fail('INDEX_KEY_INVALID');
  const root=path.resolve(entry.bundleRoot);
  if(bundlePaths.has(root))fail('INDEX_DUPLICATE_BUNDLE');
  bundlePaths.add(root);
  const mf=path.join(root,'manifest.json'),sig=path.join(root,'manifest.sig');
  checkSignedBundle({bundleRoot:root,manifestFile:mf,signatureFile:sig,
    publicKeyFile:entry.publicKeyFile,vaultFile:entry.vaultFile,expectedKeySha256:entry.keySha256});
  const m=JSON.parse(fs.readFileSync(mf,'utf8'));
  const packageHash=canonicalId(m);
  const databaseHash=m.components.find(x=>x.role==='database')?.sha256.toLowerCase();
  if(!databaseHash||!key.test(databaseHash))fail('DATABASE_HASH_INVALID');
  if(captureIds.has(m.captureId)&&captureIds.get(m.captureId)!==packageHash)fail('CAPTURE_ID_COLLISION');
  captureIds.set(m.captureId,packageHash);
  if(packages.has(packageHash))identicalCopies++;
  packages.set(packageHash,(packages.get(packageHash)||0)+1);
  dbSnapshots.set(databaseHash,(dbSnapshots.get(databaseHash)||0)+1);
  releases.add(m.release);
  keys.add(entry.keySha256.toLowerCase());
 }
 return {signedBundles:index.entries.length,distinctPackages:packages.size,
  distinctDatabasePoints:dbSnapshots.size,identicalPackageCopies:identicalCopies,
  releaseLabels:releases.size,trustedSignerKeys:keys.size,
  // Same encrypted file copied N times is ONE database point, not N.
  allManifestsCryptographicallyVerified:true,
  captureDateIndependentlyVerified:false};
}
function cli(args){
 if(args.length!==2||args[0]!=='--inventory')fail('USAGE');
 const r=summarizeIndex(args[1]);
 console.log(['=== ROTA62 GUARDIAN V6.1 SIGNED RECOVERY INVENTORY ===',
  'SIGNED_BACKUP_BUNDLES='+r.signedBundles,
  'DISTINCT_FULL_PACKAGES='+r.distinctPackages,
  'DISTINCT_DATABASE_RECOVERY_POINTS='+r.distinctDatabasePoints,
  'IDENTICAL_FULL_PACKAGE_COPIES='+r.identicalPackageCopies,
  'RELEASE_LABEL_COUNT='+r.releaseLabels,
  'TRUSTED_SIGNER_KEYS='+r.trustedSignerKeys,
  'MANIFEST_SIGNATURES_AND_ARTIFACT_HASHES=PASS',
  'CAPTURE_DATES_INDEPENDENTLY_ATTESTED=NO',
  'DATABASE_CONTENT_RESTORED=NO','SITE_API_STORAGE_RESTORED=NO',
  'PRODUCTION_TOUCHED=NO','RTO_4_TO_6_HOURS_PROVEN=NO','END_REPORT_OK'].join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{cli(process.argv.slice(2));}
 catch(e){
  const known=new Set(['USAGE','INDEX_PATH_INVALID','INDEX_INVALID','INDEX_JSON_INVALID',
    'INDEX_SCHEMA_INVALID','INDEX_KEY_INVALID','INDEX_DUPLICATE_BUNDLE',
    'CAPTURE_ID_COLLISION','MANIFEST_COMPONENT_INVALID','DATABASE_HASH_INVALID']);
  console.log('=== ROTA62 GUARDIAN V6.1 SIGNED RECOVERY INVENTORY ===\nSTATUS=BLOCKED_'+
   (known.has(e.message)?e.message:'SIGNED_BUNDLE_INVALID_OR_UNTRUSTED')+
   '\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

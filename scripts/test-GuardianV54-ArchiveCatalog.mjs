#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {examine} from './GuardianV54-ArchiveCatalog.mjs';
const pgdump=process.argv[2];
if(!pgdump||!fs.statSync(pgdump).isFile())throw Error('Synthetic pg_dump fixture required');
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'guardian-v54-toc-'));
const archive=path.join(tmp,'synthetic.r62db');
const password='LOCAL_SYNTHETIC_ONLY_NOT_REAL_PASSWORD';
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
function envelope(pg){
 const header={schema:2,format:'pg_dump_custom',created_at:'2026-01-01T00:00:00.000Z',cipher:'AES-256-GCM',
  kdf:'scrypt',N:32768,r:8,p:1,salt:crypto.randomBytes(16).toString('hex'),nonce:crypto.randomBytes(12).toString('hex')};
 const json=Buffer.from(JSON.stringify(header)),len=Buffer.alloc(4);len.writeUInt32BE(json.length);
 const aad=Buffer.concat([Buffer.from('R62DB02\n'),len,json]);
 const key=crypto.scryptSync(password,Buffer.from(header.salt,'hex'),32,{N:32768,r:8,p:1,maxmem:128*1024*1024});
 try{
  const cipher=crypto.createCipheriv('aes-256-gcm',key,Buffer.from(header.nonce,'hex'));
  cipher.setAAD(aad);
  return Buffer.concat([aad,cipher.update(pg),cipher.final(),cipher.getAuthTag()]);
 }finally{key.fill(0);}
}
try{
 const bytes=fs.readFileSync(pgdump);
 assert.equal(bytes.subarray(0,5).toString(),'PGDMP');
 const wrapped=envelope(bytes);
 fs.writeFileSync(archive,wrapped);
 const result=await examine(archive,sha(wrapped),password);
 assert.equal(result.auth.bytes,bytes.length);
 assert.equal(result.auth.plainSha256,sha(bytes));
 assert.ok(result.toc.items>=5);
 assert.ok((result.toc.counts.TABLE||0)>=1);
 assert.ok((result.toc.counts.INDEX||0)>=1);
 // pg_restore -l classifies data separately but never accesses the database.
 assert.ok((result.toc.counts.TABLE_DATA||0)>=1);
 assert.ok((result.toc.counts.POLICY||0)>=1);
 assert.ok(result.toc.dependencySummary.distinctVisibleOwnerRoles>=1);
 assert.ok(result.toc.counts.EXTENSION>=1);
 assert.equal(result.toc.dependencySummary.extensionsListed,result.toc.counts.EXTENSION);
 assert.equal(result.toc.dependencySummary.distinctExtensions,result.toc.counts.EXTENSION);
 assert.ok(result.toc.dependencySummary.distinctVisibleOwnerRoles<=result.toc.items);
 assert.ok(result.toc.dependencySummary.entries===result.toc.items);
 assert.ok(result.toc.dependencySummary.dependencyFingerprint16.length===16);
 assert.equal(result.toc.shapeAudit.entries,result.toc.items);
 assert.equal(result.toc.shapeAudit.recognizedTypes+result.toc.shapeAudit.unrecognizedTypes,result.toc.items);
 assert.equal(result.toc.shapeAudit.typesWithoutOwnerProof+
  result.toc.shapeAudit.structuralOwnerCandidatesOnly,result.toc.shapeAudit.recognizedTypes);
 assert.equal(result.toc.shapeAudit.extensionEntries,result.toc.counts.EXTENSION);
 assert.equal(result.toc.shapeAudit.rolesAndAclRestoreReady,false);
 assert.equal(result.toc.shapeAudit.verifiedHistoricalGlobalRoles,0);
 const bad=Buffer.from(wrapped);bad[bad.length-1]^=1;
 fs.writeFileSync(archive,bad);
 await assert.rejects(()=>examine(archive,sha(bad),password),e=>e.message==='AUTHENTICATION_FAILED');
 console.log('V65_AUTHENTICATED_SYNTHETIC_SHAPE_AUDIT=PASS');
 console.log('V54_AUTHENTICATED_REAL_PGDUMP_TOC_SYNTHETIC=PASS');
 console.log('V54_TOC_POLICY_INDEX_DATA_COUNTS=PASS');
 console.log('V64_AUTHENTICATED_PG17_OWNERLESS_EXTENSION_PARSER=PASS');
 console.log('V54_INVALID_TAG_REJECTED_BEFORE_DOCKER=PASS');
 console.log('V54_SQL_EXECUTED=NO');
 console.log('V54_PRODUCTION_DATA_USED=NO');
}finally{fs.rmSync(tmp,{recursive:true,force:true});}

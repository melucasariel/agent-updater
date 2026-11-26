#!/usr/bin/env node
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {examine,renderSafeCatalogReport} from './GuardianV54-ArchiveCatalog.mjs';
import {parseSafeReport} from './GuardianV55-RecoveryPreflight.mjs';
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
 assert.equal(result.toc.blindSpotAudit.entries,result.toc.items);
 assert.equal(result.toc.blindSpotAudit.recognizedPublicPgKindsNotInV65+
   result.toc.blindSpotAudit.otherUnknownShapes,result.toc.shapeAudit.unrecognizedTypes);
 assert.equal(result.toc.blindSpotAudit.nonstandardInCandidateOnlyTypes+
   result.toc.blindSpotAudit.nonstandardInNoOwnerProofTypes,result.toc.shapeAudit.nonstandardLastTokens);
 assert.equal(result.toc.blindSpotAudit.historicalRolesVerified,false);
 assert.equal(result.toc.blindSpotAudit.restoreReady,false);
 assert.equal(result.toc.tableScopeAudit.catalogItems,result.toc.items);
 assert.equal(result.toc.tableScopeAudit.tableEntries,result.toc.counts.TABLE);
 assert.equal(result.toc.tableScopeAudit.tableDataEntries,result.toc.counts.TABLE_DATA);
 assert.equal(result.toc.tableScopeAudit.publicSchemaTableEntries+
  result.toc.tableScopeAudit.otherSimpleSchemaTableEntries+
  result.toc.tableScopeAudit.noSchemaTableEntries+
  result.toc.tableScopeAudit.complexOrAmbiguousSchemaTableEntries,
  result.toc.counts.TABLE);
 assert.equal(result.toc.tableScopeAudit.originalUserTablesValidated,false);
 assert.equal(result.toc.tableScopeAudit.sqlExecuted,false);
 assert.equal(result.toc.tableDataPairs.entries,result.toc.items);
 assert.equal(result.toc.tableDataPairs.tableEntries,result.toc.counts.TABLE);
 assert.equal(result.toc.tableDataPairs.dataEntries,result.toc.counts.TABLE_DATA);
 assert.equal(result.toc.tableDataPairs.structurallyPaired+
  result.toc.tableDataPairs.unpairedSimpleTableEntries+
  result.toc.tableDataPairs.ambiguousTableEntries,result.toc.counts.TABLE);
 assert.equal(result.toc.tableDataPairs.structurallyPaired+
  result.toc.tableDataPairs.unpairedSimpleDataEntries+
  result.toc.tableDataPairs.ambiguousDataEntries,result.toc.counts.TABLE_DATA);
 assert.equal(result.toc.tableDataPairs.rowCountsVerified,false);
 assert.equal(result.toc.tableDataPairs.productionTouched,false);
 assert.equal(result.toc.tableDataPairs.ambiguousTableQuoted+
  result.toc.tableDataPairs.ambiguousTableUnicode+
  result.toc.tableDataPairs.ambiguousTableOther,
  result.toc.tableDataPairs.ambiguousTableEntries);
 assert.equal(result.toc.tableDataPairs.simpleTableWithoutData+
  result.toc.tableDataPairs.simpleTableOwnerMismatch+
  result.toc.tableDataPairs.simpleNonuniqueTables,
  result.toc.tableDataPairs.unpairedSimpleTableEntries);
 assert.equal(result.toc.tableDataPairs.simpleDataWithoutTable+
  result.toc.tableDataPairs.simpleDataOwnerMismatch+
  result.toc.tableDataPairs.simpleNonuniqueData,
  result.toc.tableDataPairs.unpairedSimpleDataEntries);

 // pg_dump PG17 partitioned parent has TABLE without an independent
 // TABLE DATA entry; emptiness/missing records must NOT be inferred.
 assert.ok(result.toc.counts.TABLE>=4);
 assert.ok(result.toc.tableDataPairs.structurallyPaired>=1);
 assert.ok(result.toc.tableDataPairs.unpairedSimpleTableEntries>=1);
 assert.equal(result.toc.tableDataPairs.allTableDataVerified,false);

 const safe=renderSafeCatalogReport(result);
 assert.equal(typeof safe,'string');
 assert.ok(safe.includes('AUDIT_PROFILE=V68_STRUCTURAL_TABLE_DATA'));
 assert.ok(safe.includes('PAIR_ROWS_VERIFIED=NO'));
 assert.ok(safe.includes('PAIR_REASON_TABLE_QUOTED='));
 assert.ok(safe.includes('PAIR_REASON_OWNER_TABLE='));
 assert.ok(safe.includes('PAIR_REASON_NONUNIQUE_DATA='));
 assert.throws(()=>parseSafeReport(safe.replace(/PAIR_REASON_TABLE_QUOTED=\d+/,'PAIR_REASON_TABLE_QUOTED=999')),
  e=>e.message==='PAIR_REASON_COUNTER_INCONSISTENT');

 assert.ok(safe.endsWith('END_REPORT_OK'));
 assert.equal(safe.split('\n').length<=100,true);
 // The exact renderer used by main() must pass the actual V5.5 parser.
 const parsed=parseSafeReport(safe);
 assert.equal(parsed.items,result.toc.items);
 assert.equal(parsed.counts.TABLE,result.toc.tableDataPairs.tableEntries);
 assert.equal(parsed.counts.TABLE_DATA,result.toc.tableDataPairs.dataEntries);
 for(const secret of ['events_state_idx','events_read','LOCAL_SYNTHETIC_ONLY_NOT_REAL_PASSWORD'])
  assert.equal(safe.includes(secret),false);
 assert.throws(()=>parseSafeReport(safe.replace('PAIR_ROWS_VERIFIED=NO','PAIR_ROWS_VERIFIED=YES')),
  e=>e.message==='PAIR_REPORT_INCOMPLETE');


 // Explicit opt-in deep scan: PostgreSQL writes its generated restore script
 // ONLY to /dev/null inside a networkless, readonly Docker container. No DB.
 const deep=await examine(archive,sha(wrapped),password,{deepRead:true});
 assert.equal(deep.deepRead.fullRead,true);
 assert.equal(deep.deepRead.sqlExecuted,false);
 assert.equal(deep.deepRead.rowsValidated,false);
 const deepReport=renderSafeCatalogReport(deep);
 const dp=parseSafeReport(deepReport);
 assert.equal(dp.items,result.toc.items);
 assert.ok(deepReport.includes('DEEP_FULL_ARCHIVE_READ=PASS'));
 assert.ok(deepReport.includes('DEEP_ROWS_VALIDATED=NO'));
 assert.ok(deepReport.includes('DEEP_SQL_EXECUTED=NO'));
 assert.throws(()=>parseSafeReport(deepReport.replace('DEEP_ROWS_VALIDATED=NO','DEEP_ROWS_VALIDATED=YES')),
  e=>e.message==='DEEP_REPORT_INCOMPLETE');
 assert.throws(()=>parseSafeReport(deepReport.replace('DEEP_SQL_EXECUTED=NO','DEEP_SQL_EXECUTED=YES')),
  e=>e.message==='DEEP_REPORT_INCOMPLETE');

 const bad=Buffer.from(wrapped);bad[bad.length-1]^=1;
 fs.writeFileSync(archive,bad);
 await assert.rejects(()=>examine(archive,sha(bad),password),e=>e.message==='AUTHENTICATION_FAILED');
 console.log('V68_PG17_PARTITION_PARENT_NOT_FALSE_DATA_LOSS=PASS');
 console.log('V69_AUTHENTICATED_SYNTHETIC_FULL_STREAM_NO_SQL=PASS');
 console.log('V68_AUTHENTICATED_REAL_RENDERER_V55_PARSER_CONTRACT=PASS');
 console.log('V68_AUTHENTICATED_SYNTHETIC_TABLE_DATA_PAIRS=PASS');
 console.log('V67_AUTHENTICATED_SYNTHETIC_TABLE_SCOPE=PASS');
 console.log('V66_AUTHENTICATED_SYNTHETIC_BLIND_AUDIT=PASS');
 console.log('V65_AUTHENTICATED_SYNTHETIC_SHAPE_AUDIT=PASS');
 console.log('V54_AUTHENTICATED_REAL_PGDUMP_TOC_SYNTHETIC=PASS');
 console.log('V54_TOC_POLICY_INDEX_DATA_COUNTS=PASS');
 console.log('V64_AUTHENTICATED_PG17_OWNERLESS_EXTENSION_PARSER=PASS');
 console.log('V54_INVALID_TAG_REJECTED_BEFORE_DOCKER=PASS');
 console.log('V54_SQL_EXECUTED=NO');
 console.log('V54_PRODUCTION_DATA_USED=NO');
}finally{fs.rmSync(tmp,{recursive:true,force:true});}

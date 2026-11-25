import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {compareCatalogs} from './GuardianV57-CompareCatalog.mjs';
const root=fs.mkdtempSync(path.join(os.tmpdir(),'r62-v57-catalog-'));
const src=path.join(root,'source.txt'),dst=path.join(root,'dest.txt');
function write(f,rows){fs.writeFileSync(f,rows.sort().join('\n')+'\n','utf8');}
try{
 const base=[
  'SCHEMA|fixture|owner',
  'SCHEMA_ACL|NONE',
  'TABLE|jobs|r|owner|true|false',
  'COLUMN|jobs|1|id|integer|true|NONE',
  'TABLE_ACL|jobs|reader:SELECT:false:owner',
  'DEFAULT_ACL|owner|r|reader:SELECT:false:owner',
  'INDEX|jobs|jobs_pkey|CREATE UNIQUE INDEX jobs_pkey',
  'POLICY|jobs|jobs_select|r|true|true|NONE|PUBLIC',
  'FUNCTION|f|()|owner|false|424547494E'
 ];
 write(src,[...base]);write(dst,[...base]);
 const okay=compareCatalogs(src,dst);
 assert.equal(okay.equal,true);
 assert.equal(okay.categoryCounts.find(x=>x.category==='TABLE_ACL').countMatch,true);
 write(dst,base.map(x=>x.replace('reader:SELECT:false:owner','reader:UPDATE:false:owner')));
 const changed=compareCatalogs(src,dst);
 assert.equal(changed.equal,false);
 assert.equal(changed.categoryCounts.every(x=>x.countMatch),true);
 // A semantic ACL change is detectable even with exactly matching category counts.
 assert.notEqual(changed.sourceFingerprint16,changed.destinationFingerprint16);
 fs.writeFileSync(dst,'TABLE|a\nSCHEMA|z\n');
 assert.throws(()=>compareCatalogs(src,dst),e=>e.message==='CATALOG_NOT_SORTED');
 write(dst,[...base,'SECRET|somevalue']);
 assert.throws(()=>compareCatalogs(src,dst),e=>e.message==='UNKNOWN_CATALOG_CATEGORY');
 fs.writeFileSync(dst,Buffer.from([0,1,2]));
 assert.throws(()=>compareCatalogs(src,dst),e=>e.message==='CATALOG_NUL_BLOCKED');
 console.log('V57_CANONICAL_CATALOG_COMPARE_MATCH=PASS');
 console.log('V57_SEMANTIC_ACL_CHANGE_WITH_EQUAL_COUNTS=DETECTED');
 console.log('V57_SORTING_UNKNOWN_TYPES_BINARY_INPUT=BLOCKED');
 console.log('V57_NO_NETWORK_OR_DATABASE_ACCESS=YES');
}finally{fs.rmSync(root,{recursive:true,force:true});}

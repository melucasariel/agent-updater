#!/usr/bin/env node
// Synthetic-only experiment: distinguish pg_restore --list from a full
// output-to-/dev/null payload expansion, with NO DB and NO SQL execution.
// NEVER point this test at a real backup. It takes an invented PGDMP fixture.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';

const p=process.argv[2];
if(process.argv.length!==3||!p||!p.endsWith('synthetic.dump'))throw Error('SYNTHETIC_FIXTURE_REQUIRED');
const pg=fs.readFileSync(p);
if(pg.length<64||pg.subarray(0,5).toString('ascii')!=='PGDMP')throw Error('SYNTHETIC_CUSTOM_DUMP_REQUIRED');
const image='postgres:17-alpine';
const base=['run','--rm','-i','--pull','never','--network','none',
 '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges',
 '--pids-limit','32','--memory','256m','--cpus','1','--user','999:999',
 '--entrypoint','pg_restore',image];
function invoke(input,options){
 const result=spawnSync('docker',[...base,...options],{
  input,stdio:['pipe','ignore','ignore'],timeout:90000,windowsHide:true
 });
 return result.status===0&&!result.error;
}
assert.ok(invoke(pg,['--list']),'SYNTHETIC_TOC_NOT_READABLE');
assert.ok(invoke(pg,['--file=/dev/null']),'SYNTHETIC_FULL_EXPANSION_NOT_READABLE');
// The truncated file keeps its PGDMP signature but not complete payload.
// It must not be accepted by full expansion even if the TOC was readable.
const truncated=pg.subarray(0,pg.length-Math.min(64,Math.floor(pg.length/8)));
assert.ok(!invoke(truncated,['--file=/dev/null']),'TRUNCATED_PAYLOAD_ACCEPTED');
assert.ok(!invoke(Buffer.from('PGDMP'+'.'.repeat(512)),['--file=/dev/null']),
 'BAD_PGDMP_BODY_ACCEPTED');
console.log('V69_PG17_SYNTHETIC_FULL_EXPANSION_TO_DEV_NULL=PASS');
console.log('V69_TRUNCATION_AND_CORRUPT_PAYLOAD_REJECTED=PASS');
console.log('V69_NO_DATABASE_NO_SQL_NO_NETWORK_NO_PLAINTEXT_FILE=YES');

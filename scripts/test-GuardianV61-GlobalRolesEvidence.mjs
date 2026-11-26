#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {scanGlobals} from './GuardianV61-GlobalRolesEvidence.mjs';
const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'r62-v61-global-'));
const file=path.join(tmp,'globals.sql');
const raw=[
 '-- PostgreSQL database cluster dump\n',
 '-- This is a synthetic fixture, not any real credential.\n',
 'CREATE ROLE test_owner;\n',
 "ALTER ROLE test_owner WITH LOGIN PASSWORD 'SYNTHETIC_ONLY_PASSWORD_NEVER_REAL';\n",
 'CREATE ROLE test_reader;\n',
 'GRANT test_reader TO test_owner;\n',
 'ALTER ROLE test_owner WITH NOSUPERUSER NOBYPASSRLS;\n',
 'REVOKE test_reader FROM test_owner;\n',
 'DO $$ BEGIN RAISE NOTICE \'synthetic\'; END $$;\n'
].join('');
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
try{
 fs.writeFileSync(file,raw,{mode:0o600});
 const info=scanGlobals(file,hash(raw));
 assert.equal(info.CREATE_ROLE_STATEMENTS_INDICATED,'2');
 assert.equal(info.ALTER_ROLE_STATEMENTS_INDICATED,'2');
 assert.equal(info.GRANT_STATEMENTS_INDICATED,'1');
 assert.equal(info.REVOKE_STATEMENTS_INDICATED,'1');
 assert.equal(info.PASSWORD_CLAUSE_INDICATED,'YES');
 assert.equal(info.POTENTIALLY_UNSAFE_STATEMENTS_INDICATED,'YES');
 assert.equal(info.GLOBALS_EXECUTED,'NO');
 assert.ok(!JSON.stringify(info).includes('SYNTHETIC_ONLY_PASSWORD_NEVER_REAL'));
 assert.throws(()=>scanGlobals(file,'0'.repeat(64)),e=>e.message==='GLOBALS_SHA_MISMATCH');
 fs.writeFileSync(file,Buffer.from([0,0,1,2,...Buffer.alloc(40)]));
 assert.throws(()=>scanGlobals(file,hash(fs.readFileSync(file))),e=>e.message==='GLOBALS_ENCODING_INVALID');
 console.log('V61_GLOBALS_OFFLINE_RISK_COUNTS=PASS');
 console.log('V61_WRONG_HASH_AND_BINARY_INPUT=BLOCKED');
 console.log('V61_PASSWORD_OR_ROLE_NAMES_IN_REPORT=NO');
 console.log('V61_SQL_EXECUTED=NO');
}finally{fs.rmSync(tmp,{recursive:true,force:true});}

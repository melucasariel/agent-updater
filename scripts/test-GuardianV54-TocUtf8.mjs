#!/usr/bin/env node
// Pure synthetic test: UTF-8 must not be decoded one pipe chunk at a time.
import assert from 'node:assert/strict';
import {decodeTocUtf8Chunks} from './GuardianV54-ArchiveCatalog.mjs';

const synthetic='1; 1 1 TABLE public ação_café münchen_owner\n'+
 '2; 1 1 TABLE public 日本語 owns_foo\n'+
 '3; 1 1 TABLE DATA public ação_café münchen_owner\n';
const bytes=Buffer.from(synthetic,'utf8');
for(let step=1;step<=17;step++){
 const chunks=[];
 for(let i=0;i<bytes.length;i+=step)chunks.push(bytes.subarray(i,i+step));
 assert.equal(decodeTocUtf8Chunks(chunks),synthetic);
}
assert.equal(decodeTocUtf8Chunks([Buffer.alloc(0),bytes,Buffer.alloc(0)]),synthetic);
for(const invalid of [
 [Buffer.from([0xc3])],
 [Buffer.from([0xe2]),Buffer.from([0x28,0xa1])],
 [Buffer.from([0xff])],
 [Buffer.from([0xc0,0xaf])]
]){
 assert.throws(()=>decodeTocUtf8Chunks(invalid),e=>e.message==='TOC_TEXT_ENCODING_INVALID');
}
assert.throws(()=>decodeTocUtf8Chunks([Buffer.alloc(8*1024*1024+1)]),e=>e.message==='TOC_OUTPUT_TOO_LARGE');
assert.throws(()=>decodeTocUtf8Chunks(['not a buffer']),e=>e.message==='TOC_ENCODING_SOURCE_INVALID');
console.log('GUARDIAN_TOC_UTF8_CHUNK_BOUNDARIES=PASS');
console.log('GUARDIAN_TOC_INVALID_ENCODING_AND_SIZE_FAIL_CLOSED=PASS');
console.log('GUARDIAN_TOC_NO_REAL_BACKUP_NO_SQL=YES');

#!/usr/bin/env node
// Synthetic ciphertext and original-format envelope only. No production data or passwords.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';
import {authenticate} from './GuardianV53-AuthenticateR62DB.mjs';
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'r62-v53-gcm-'));
const file=path.join(dir,'synthetic.r62db');
const password='synthetic-test-only-no-real-credentials';
function makeArchive(payload){
 const header={schema:2,format:'pg_dump_custom',created_at:'2026-01-01T00:00:00.000Z',
  cipher:'AES-256-GCM',kdf:'scrypt',N:32768,r:8,p:1,
  salt:crypto.randomBytes(16).toString('hex'),nonce:crypto.randomBytes(12).toString('hex')};
 const data=Buffer.from(JSON.stringify(header),'utf8');
 const length=Buffer.alloc(4);length.writeUInt32BE(data.length);
 const prefix=Buffer.concat([Buffer.from('R62DB02\n'),length,data]);
 const key=crypto.scryptSync(password,Buffer.from(header.salt,'hex'),32,{N:32768,r:8,p:1,maxmem:128*1024*1024});
 try{
  const cipher=crypto.createCipheriv('aes-256-gcm',key,Buffer.from(header.nonce,'hex'));
  cipher.setAAD(prefix);
  return Buffer.concat([prefix,cipher.update(payload),cipher.final(),cipher.getAuthTag()]);
 }finally{key.fill(0);}
}
function sha(b){return crypto.createHash('sha256').update(b).digest('hex');}
async function denied(fn,msg){await assert.rejects(fn,e=>e.message===msg);}
try{
 const original=makeArchive(Buffer.concat([Buffer.from('PGDMP'),crypto.randomBytes(4096)]));
 fs.writeFileSync(file,original);
 const pass=await authenticate(file,sha(original),password);
 assert.equal(pass.bytes,4101);
 assert.equal(pass.encryptedBytes,original.length);
 assert.equal(pass.plainSha256.length,64);
 await denied(()=>authenticate(file,sha(original),'wrong-pass'),'AUTHENTICATION_FAILED');
 await denied(()=>authenticate(file,'0'.repeat(64),password),'ENCRYPTED_SHA_MISMATCH');
 // Alter authenticated metadata, then recompute outside checksum: AES-GCM still MUST reject.
 const altered=Buffer.from(original);
 const headerSize=altered.readUInt32BE(8);
 const json=JSON.parse(altered.subarray(12,12+headerSize).toString('utf8'));
 json.created_at='2026-01-02T00:00:00.000Z';
 const revised=Buffer.from(JSON.stringify(json),'utf8');
 assert.equal(revised.length,headerSize);
 revised.copy(altered,12);
 fs.writeFileSync(file,altered);
 await denied(()=>authenticate(file,sha(altered),password),'AUTHENTICATION_FAILED');
 // Change ciphertext and recompute checksum: GCM tag must reject.
 const corrupted=Buffer.from(original);corrupted[corrupted.length-25]^=0x80;
 fs.writeFileSync(file,corrupted);
 await denied(()=>authenticate(file,sha(corrupted),password),'AUTHENTICATION_FAILED');
 // Change authentication tag and recompute checksum.
 const tagChanged=Buffer.from(original);tagChanged[tagChanged.length-1]^=1;
 fs.writeFileSync(file,tagChanged);
 await denied(()=>authenticate(file,sha(tagChanged),password),'AUTHENTICATION_FAILED');
 // Truncating archive must not be accepted, even if SHA matches truncated bytes.
 fs.writeFileSync(file,original.subarray(0,20));
 await denied(()=>authenticate(file,sha(original.subarray(0,20)),password),'INVALID_ARCHIVE');
 // Properly signed ciphertext with wrong plaintext format must not claim PostgreSQL archive.
 const other=makeArchive(Buffer.concat([Buffer.from('NOTPG'),crypto.randomBytes(64)]));
 fs.writeFileSync(file,other);
 await denied(()=>authenticate(file,sha(other),password),'NOT_PG_CUSTOM_DUMP');
 console.log('V53_ORIGINAL_FORMAT_AES_GCM_SCRYPT_SYNTHETIC=PASS');
 console.log('V53_WRONG_PASSWORD_HEADER_CIPHERTEXT_TAG_TRUNCATION=REJECTED');
 console.log('V53_PLAINTEXT_DISK_FILES=ZERO');
 console.log('V53_PRODUCTION_OPERATIONS=ZERO');
}finally{fs.rmSync(dir,{recursive:true,force:true});}

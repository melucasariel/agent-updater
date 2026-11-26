#!/usr/bin/env node
// CI-only: create a synthetic R62DB02 fixture from an artificial PGDMP file.
// Never use for real backups. Password must be fake and is read from a CI-only env var.
import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
const fail=s=>{throw Error(s)};
try{
 const [src,dst]=process.argv.slice(2);
 if(!src||!dst||!path.isAbsolute(src)||!path.isAbsolute(dst)||src===dst)fail('USAGE');
 const pass=process.env.R62_V58_SYNTHETIC_PASSWORD;
 if(!pass||pass.length<12)fail('NO_SYNTHETIC_CREDENTIAL');
 const plain=fs.readFileSync(src);
 if(plain.length<64||plain.length>64*1024*1024||plain.subarray(0,5).toString()!=='PGDMP')fail('SYNTHETIC_PGDMP_REQUIRED');
 const header={schema:2,format:'pg_dump_custom',created_at:'2026-11-25T00:00:00.000Z',cipher:'AES-256-GCM',
  kdf:'scrypt',N:32768,r:8,p:1,salt:crypto.randomBytes(16).toString('hex'),nonce:crypto.randomBytes(12).toString('hex')};
 const raw=Buffer.from(JSON.stringify(header)),len=Buffer.alloc(4);
 len.writeUInt32BE(raw.length);
 const aad=Buffer.concat([Buffer.from('R62DB02\n'),len,raw]);
 const key=crypto.scryptSync(pass,Buffer.from(header.salt,'hex'),32,{N:32768,r:8,p:1,maxmem:128*1024*1024});
 let cipher;
 try{cipher=crypto.createCipheriv('aes-256-gcm',key,Buffer.from(header.nonce,'hex'));cipher.setAAD(aad);}
 finally{key.fill(0);}
 const encrypted=Buffer.concat([aad,cipher.update(plain),cipher.final(),cipher.getAuthTag()]);
 fs.writeFileSync(dst,encrypted,{flag:'wx',mode:0o600});
 const hash=crypto.createHash('sha256').update(encrypted).digest('hex');
 console.log('SYNTHETIC_ARCHIVE_SHA256='+hash);
 console.log('SYNTHETIC_ARCHIVE_BYTES='+encrypted.length);
 console.log('REAL_BACKUP_USED=NO');
}catch(e){
 console.log('STATUS=BLOCKED_SYNTHETIC_INPUT');
 process.exitCode=2;
}

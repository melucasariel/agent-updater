#!/usr/bin/env node
// Guardian V5.8: SYNTHETIC-ONLY GCM-authenticated stream -> disposable PostgreSQL17.
// Does NOT accept real operator backup passwords or restore user/production databases.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {spawn,spawnSync} from 'node:child_process';
import {pipeline} from 'node:stream/promises';
import {Transform} from 'node:stream';
import {fileURLToPath} from 'node:url';
import {authenticate} from './GuardianV53-AuthenticateR62DB.mjs';
const fail=x=>{throw Error(x);};
const scrypt={N:32768,r:8,p:1,maxmem:128*1024*1024};
function docker(args){
 const r=spawnSync('docker',args,{encoding:'utf8',timeout:20000,windowsHide:true,maxBuffer:1024*1024});
 if(r.error||r.status!==0)fail('DOCKER_PROBE_FAILED');
 return r.stdout.trim();
}
function verifyTarget(name){
 if(!/^r62v58_(?:dest|fixture)_[a-z0-9]{6,20}$/.test(name||''))fail('TARGET_NAME_BLOCKED');
 if(process.env.DOCKER_HOST||process.env.DOCKER_CONTEXT)fail('REMOTE_DOCKER_BLOCKED');
 const context=docker(['context','show']);
 if(!['default','desktop-linux'].includes(context))fail('DOCKER_CONTEXT_BLOCKED');
 const cfg=JSON.parse(docker(['context','inspect',context]))?.[0];
 const endpoint=cfg?.Endpoints?.docker?.Host;
 if(typeof endpoint!=='string'||!(endpoint.startsWith('unix://')||endpoint.startsWith('npipe://')))fail('REMOTE_DOCKER_BLOCKED');
 const c=JSON.parse(docker(['inspect','--type','container',name]))?.[0];
 if(!c||c.Name!=='/'+name||c.State?.Running!==true||
  c.Config?.Labels?.['r62.guardian.synthetic.v58']!=='true')fail('TARGET_NOT_SYNTHETIC');
 if(c.HostConfig?.Privileged||['host'].includes(c.HostConfig?.NetworkMode)||
  c.HostConfig?.PidMode==='host'||c.HostConfig?.IpcMode==='host')fail('TARGET_HOST_CONFIG');
 if((c.Mounts||[]).some(x=>x.Type!=='volume'||x.Destination!=='/var/lib/postgresql/data'))fail('TARGET_MOUNTS_BLOCKED');
 const nets=Object.keys(c.NetworkSettings?.Networks||{});
 if(nets.length!==1)fail('TARGET_NETWORK_COUNT');
 const net=JSON.parse(docker(['network','inspect',nets[0]]))?.[0];
 if(!net?.Internal||net?.Name!==nets[0])fail('TARGET_NETWORK_NOT_INTERNAL');
 for(const p of Object.values(c.NetworkSettings?.Ports||{}))if(Array.isArray(p)&&p.length)fail('TARGET_PUBLISHED_PORTS');
 if(!String(c.Config?.Image||'').includes('postgres'))fail('TARGET_IMAGE_BLOCKED');
 if(!/pg_restore \(PostgreSQL\) 17(?:\.|\s|$)/.test(docker(['exec','--user','postgres',name,'pg_restore','--version'])))fail('TARGET_VERSION_BLOCKED');
 return c.Id;
}
function parseEnvelope(file){
 const stat=fs.lstatSync(file);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size<64||stat.size>64*1024*1024)fail('ARCHIVE_SIZE_BLOCKED');
 const fd=fs.openSync(file,'r');
 try{
  const pre=Buffer.alloc(12);fs.readSync(fd,pre,0,12,0);
  if(pre.subarray(0,8).toString()!=='R62DB02\n')fail('ARCHIVE_MAGIC');
  const size=pre.readUInt32BE(8);
  if(size<16||size>4096||12+size+16>=stat.size)fail('ARCHIVE_HEADER');
  const raw=Buffer.alloc(size);fs.readSync(fd,raw,0,size,12);
  let j;try{j=JSON.parse(raw.toString('utf8'));}catch{fail('ARCHIVE_HEADER_JSON');}
  if(j.schema!==2||j.format!=='pg_dump_custom'||j.cipher!=='AES-256-GCM'||j.kdf!=='scrypt'||
   j.N!==32768||j.r!==8||j.p!==1||!/^[a-f0-9]{32}$/.test(j.salt)||!/^[a-f0-9]{24}$/.test(j.nonce))fail('ARCHIVE_PARAMETERS');
  const tag=Buffer.alloc(16);fs.readSync(fd,tag,0,16,stat.size-16);
  return {j,aad:Buffer.concat([pre,raw]),tag,start:12+size,end:stat.size-17};
 }finally{fs.closeSync(fd);}
}
async function checksum(file){
 const h=crypto.createHash('sha256');
 for await(const b of fs.createReadStream(file))h.update(b);
 return h.digest('hex');
}
export async function restoreSynthetic({archive,expectedSha256,password,target}){
 if(!path.isAbsolute(archive)||!/^[a-f0-9]{64}$/i.test(expectedSha256||'')||typeof password!=='string'||!password)fail('INVALID_ARGUMENTS');
 const originalContainerId=verifyTarget(target);
 const initial=await checksum(archive);
 if(initial!==expectedSha256.toLowerCase())fail('ARCHIVE_SHA_MISMATCH');
 // First pass verifies COMPLETE AES-GCM tag before ANY SQL is executed.
 const verified=await authenticate(archive,initial,password);
 if(verified.bytes<64)fail('ARCHIVE_TOO_SMALL');
 if(await checksum(archive)!==initial)fail('ARCHIVE_CHANGED_BETWEEN_PASSES');
 if(verifyTarget(target)!==originalContainerId)fail('TARGET_CHANGED');
 const meta=parseEnvelope(archive);
 const key=crypto.scryptSync(password,Buffer.from(meta.j.salt,'hex'),32,scrypt);
 const decryptor=crypto.createDecipheriv('aes-256-gcm',key,Buffer.from(meta.j.nonce,'hex'));
 decryptor.setAAD(meta.aad);decryptor.setAuthTag(meta.tag);
 let child;
 try{
  child=spawn('docker',['exec','-i','--user','postgres',target,'pg_restore',
   '--exit-on-error','--single-transaction',
   '-U','postgres','-d','fixture'],{stdio:['pipe','ignore','ignore'],windowsHide:true});
  const closed=new Promise(resolve=>{
   child.once('error',()=>resolve(-1));child.once('close',code=>resolve(code));
  });
  let length=0;
  const plain=crypto.createHash('sha256');
  const monitor=new Transform({transform(b,e,cb){
   length+=b.length;
   if(length>64*1024*1024)return cb(Error('PLAINTEXT_TOO_BIG'));
   plain.update(b);cb(null,b);
  }});
  const guard=setTimeout(()=>{try{child.kill('SIGKILL');}catch{}},120000);
  let pipeOk=true;
  try{await pipeline(fs.createReadStream(archive,{start:meta.start,end:meta.end}),decryptor,monitor,child.stdin);}
  catch{pipeOk=false;try{child.kill('SIGKILL');}catch{}}
  const exit=await closed;clearTimeout(guard);
  if(!pipeOk||exit!==0)fail('RESTORE_TRANSACTION_FAILED');
  if(length!==verified.bytes||plain.digest('hex')!==verified.plainSha256)fail('PLAINTEXT_MISMATCH');
  if(await checksum(archive)!==initial)fail('ARCHIVE_CHANGED_AFTER_RESTORE');
  return {bytes:length,plaintextSha16:verified.plainSha256.slice(0,16).toUpperCase()};
 }finally{
  key.fill(0);
  if(child&&child.exitCode===null)try{child.kill('SIGKILL');}catch{}
 }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 (async()=>{
  const args=process.argv.slice(2);
  if(args.length!==8||args[0]!=='--synthetic-archive'||args[2]!=='--sha256'||
     args[4]!=='--target'||args[6]!=='--mode'||args[7]!=='synthetic-ci')fail('USAGE');
  const p=process.env.R62_V58_SYNTHETIC_PASSWORD;
  if(!p||p.length<12)fail('SYNTHETIC_CREDENTIAL_REQUIRED');
  const r=await restoreSynthetic({archive:args[1],expectedSha256:args[3],target:args[5],password:p});
  console.log(['=== ROTA62 GUARDIAN V5.8 SYNTHETIC ENCRYPTED RESTORE ===',
    'AES_GCM_AUTHENTICATED_BEFORE_SQL=YES','PG_DUMP_RESTORED_TRANSACTONALLY=YES',
    'DECRYPTED_SHA16='+r.plaintextSha16,'PLAIN_BYTES='+r.bytes,
    'NO_NEW_PLAINTEXT_FILE=YES','OWNER_ACL_FLAGS_SKIPPED=NO',
    'REAL_USER_BACKUP_RESTORED=NO','PRODUCTION_TOUCHED=NO','END_REPORT_OK'].join('\n'));
 })().catch(e=>{
  const known=new Set(['USAGE','INVALID_ARGUMENTS','TARGET_NAME_BLOCKED','REMOTE_DOCKER_BLOCKED',
   'DOCKER_CONTEXT_BLOCKED','TARGET_NOT_SYNTHETIC','TARGET_HOST_CONFIG','TARGET_MOUNTS_BLOCKED',
   'TARGET_NETWORK_COUNT','TARGET_NETWORK_NOT_INTERNAL','TARGET_PUBLISHED_PORTS','TARGET_IMAGE_BLOCKED',
   'TARGET_VERSION_BLOCKED','ARCHIVE_SIZE_BLOCKED','ARCHIVE_MAGIC','ARCHIVE_HEADER','ARCHIVE_HEADER_JSON',
   'ARCHIVE_PARAMETERS','ARCHIVE_SHA_MISMATCH','ARCHIVE_TOO_SMALL','ARCHIVE_CHANGED_BETWEEN_PASSES',
   'TARGET_CHANGED','RESTORE_TRANSACTION_FAILED','PLAINTEXT_MISMATCH','ARCHIVE_CHANGED_AFTER_RESTORE',
   'SYNTHETIC_CREDENTIAL_REQUIRED']);
  console.log('=== ROTA62 GUARDIAN V5.8 SYNTHETIC ENCRYPTED RESTORE ===\nSTATUS=BLOCKED_'+
   (known.has(e.message)?e.message:'REDACTED')+
   '\nREAL_USER_BACKUP_RESTORED=NO\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');process.exitCode=2;
 });
}

#!/usr/bin/env node
/**
 * ROTA62 Guardian V6.1 — static globals SQL candidate evidence.
 * NO SQL EXECUTION / NO ROLE NAMES / NO PASSWORDS / NO PATH OUTPUT.
 * Caller must independently supply the reference SHA256.
 * This is a conservative text scan, NEVER a SQL parser or proof of provenance.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const fail=c=>{throw Error(c);};
const HASH=/^[a-f0-9]{64}$/i;
const LIMIT=20*1024*1024;
function inspect(file,expected){
 if(typeof file!=='string'||!path.isAbsolute(file)||!HASH.test(expected||''))fail('USAGE');
 const st=fs.lstatSync(file);
 if(!st.isFile()||st.isSymbolicLink()||st.size<30||st.size>LIMIT)fail('GLOBALS_INPUT_INVALID');
 const input=fs.readFileSync(file);
 const actual=crypto.createHash('sha256').update(input).digest('hex');
 if(actual!==expected.toLowerCase())fail('GLOBALS_SHA_MISMATCH');
 if(input.includes(0)||!Buffer.from(input.toString('utf8'),'utf8').equals(input))fail('GLOBALS_ENCODING_INVALID');
 const sql=input.toString('utf8');
 // Recognize only indicative tokens. Do not assume complete SQL semantics:
 // strings/comments/dollar-quoting can contain misleading token sequences.
 const count=re=>(sql.match(re)||[]).length;
 const roleCreate=count(/^\s*CREATE\s+ROLE\s+/gim);
 const userCreate=count(/^\s*CREATE\s+USER\s+/gim);
 const roleAlter=count(/^\s*ALTER\s+ROLE\s+/gim);
 const grant=count(/^\s*GRANT\s+/gim);
 const revoke=count(/^\s*REVOKE\s+/gim);
 const hasPassword=/\b(?:PASSWORD|ENCRYPTED\s+PASSWORD)\s+(?:'|E'|NULL)/i.test(sql);
 const hasSuperuser=/\bSUPERUSER\b/i.test(sql);
 const hasBypass=/\bBYPASSRLS\b/i.test(sql);
 const unsafeExec=/^\s*(?:COPY\s+|DO\s+|\\\s*(?:i|include|connect|c|gexec)\b|CREATE\s+EXTENSION\b|ALTER\s+SYSTEM\b)/im.test(sql);
 const plausibleHeader=/PostgreSQL\s+database\s+cluster\s+dump|PostgreSQL\s+database\s+dump|pg_dumpall/i.test(sql);
 const attrs={
  'FILE_SHA256_MATCH':'YES',
  'GLOBALS_CANDIDATE_BYTES':String(st.size),
  'PG_DUMPALL_HEADER_INDICATOR':plausibleHeader?'YES':'NO',
  'CREATE_ROLE_STATEMENTS_INDICATED':String(roleCreate+userCreate),
  'ALTER_ROLE_STATEMENTS_INDICATED':String(roleAlter),
  'GRANT_STATEMENTS_INDICATED':String(grant),
  'REVOKE_STATEMENTS_INDICATED':String(revoke),
  'PASSWORD_CLAUSE_INDICATED':hasPassword?'YES':'NO',
  'SUPERUSER_CLAUSE_INDICATED':hasSuperuser?'YES':'NO',
  'BYPASSRLS_CLAUSE_INDICATED':hasBypass?'YES':'NO',
  'POTENTIALLY_UNSAFE_STATEMENTS_INDICATED':unsafeExec?'YES':'NO',
  'SOURCE_PROVENANCE_INDEPENDENTLY_PROVEN':'NO',
  'GLOBALS_SQL_SEMANTICALLY_VALIDATED':'NO',
  'GLOBALS_EXECUTED':'NO',
  'READY_TO_APPLY_GLOBALS':'NO',
  'PRODUCTION_TOUCHED':'NO'
 };
 return attrs;
}
export function scanGlobals(file,expected){return inspect(file,expected);}
function cli(args){
 if(args.length!==4||args[0]!=='--globals'||args[2]!=='--expected-sha256')fail('USAGE');
 const result=inspect(args[1],args[3]);
 console.log(['=== ROTA62 GUARDIAN V6.1 GLOBAL ROLES EVIDENCE ===',
  ...Object.entries(result).map(([k,v])=>k+'='+v),'END_REPORT_OK'].join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{cli(process.argv.slice(2));}
 catch(e){
  const allowed=new Set(['USAGE','GLOBALS_INPUT_INVALID','GLOBALS_SHA_MISMATCH','GLOBALS_ENCODING_INVALID']);
  console.log('=== ROTA62 GUARDIAN V6.1 GLOBAL ROLES EVIDENCE ===\nSTATUS=BLOCKED_'+
   (allowed.has(e.message)?e.message:'REDACTED')+
   '\nGLOBALS_EXECUTED=NO\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

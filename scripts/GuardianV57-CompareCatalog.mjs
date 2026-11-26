#!/usr/bin/env node
// ROTA62 Guardian V5.7 — compare canonical read-only PG17 catalog exports.
// Never connect to Docker/DB/cloud; never print names, SQL definitions, private paths.
// Inputs should be short-lived PRIVATE files from GuardianV57-CanonicalCatalog.sql.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const fail=s=>{throw Error(s);};
const CATEGORIES=new Set([
 'SCHEMA','SCHEMA_ACL','TABLE','COLUMN','TABLE_ACL','INDEX','CONSTRAINT',
 'POLICY','DEFAULT_ACL','FUNCTION','TRIGGER'
]);
const MAX_FILE=32*1024*1024, MAX_LINES=120000;
function readCatalog(filename){
 if(!path.isAbsolute(filename)||!fs.existsSync(filename))fail('INPUT_PATH_INVALID');
 const st=fs.lstatSync(filename);
 if(!st.isFile()||st.isSymbolicLink()||st.size===0||st.size>MAX_FILE)fail('CATALOG_INPUT_INVALID');
 const input=fs.readFileSync(filename);
 if(input.includes(0))fail('CATALOG_NUL_BLOCKED');
 const raw=input.toString('utf8');
 if(!Buffer.from(raw,'utf8').equals(input))fail('CATALOG_UTF8_INVALID');
 const lines=raw.trimEnd().split('\n');
 if(lines.length<3||lines.length>MAX_LINES)fail('CATALOG_LINES_INVALID');
 const counts=Object.fromEntries([...CATEGORIES].map(x=>[x,0]));
 let prior='',first=true;
 for(const value of lines){
  const line=value.endsWith('\r')?value.slice(0,-1):value;
  if(!line||line.length>100000||line.includes('\r'))fail('CATALOG_LINE_INVALID');
  if(!first&&prior>line)fail('CATALOG_NOT_SORTED');
  first=false;prior=line;
  const delim=line.indexOf('|');
  if(delim<1||!CATEGORIES.has(line.slice(0,delim)))fail('UNKNOWN_CATALOG_CATEGORY');
  counts[line.slice(0,delim)]++;
 }
 const normalized=lines.map(s=>s.endsWith('\r')?s.slice(0,-1):s).join('\n')+'\n';
 const fingerprint=crypto.createHash('sha256').update(normalized,'utf8').digest('hex');
 return {fingerprint,counts,lines:lines.length};
}
export function compareCatalogs(source,destination){
 const src=readCatalog(source),dst=readCatalog(destination);
 const all=[...CATEGORIES].sort().map(key=>({
  category:key,source:src.counts[key],destination:dst.counts[key],
  countMatch:src.counts[key]===dst.counts[key]
 }));
 return {
  equal:src.fingerprint===dst.fingerprint,
  sourceRecords:src.lines,destinationRecords:dst.lines,
  categoryCounts:all,
  // Validates equality of full canonical catalog. Counts alone never prove semantic equality.
  sourceFingerprint16:src.fingerprint.slice(0,16).toUpperCase(),
  destinationFingerprint16:dst.fingerprint.slice(0,16).toUpperCase()
 };
}
function cli(argv){
 if(argv.length!==4||argv[0]!=='--source'||argv[2]!=='--destination')fail('USAGE');
 if(path.resolve(argv[1])===path.resolve(argv[3]))fail('IDENTICAL_INPUT_PATH');
 const r=compareCatalogs(argv[1],argv[3]);
 const output=[
  '=== ROTA62 GUARDIAN V5.7 RESTORED CATALOG COMPARISON ===',
  'MODE=OFFLINE_READ_ONLY',
  'CATALOG_SOURCE_RECORDS='+r.sourceRecords,
  'CATALOG_DESTINATION_RECORDS='+r.destinationRecords,
  'CATALOG_SOURCE_SHA16='+r.sourceFingerprint16,
  'CATALOG_DESTINATION_SHA16='+r.destinationFingerprint16,
  'CATALOG_SEMANTIC_FINGERPRINT_MATCH='+(r.equal?'YES':'NO')
 ];
 for(const row of r.categoryCounts){
  output.push('CATEGORY_'+row.category+'_SOURCE='+row.source);
  output.push('CATEGORY_'+row.category+'_DESTINATION='+row.destination);
  output.push('CATEGORY_'+row.category+'_COUNT_MATCH='+(row.countMatch?'YES':'NO'));
 }
 output.push('CATALOG_OBJECT_NAMES_REDACTED=YES');
 output.push('DATABASE_ROW_CONTENT_NOT_CHECKED=YES');
 output.push('DATABASE_CONNECTIONS_OPENED=NO');
 output.push('PRODUCTION_TOUCHED=NO');
 output.push('REAL_BACKUP_RESTORED=NO');
 output.push('END_REPORT_OK');
 console.log(output.join('\n'));
 if(!r.equal)process.exitCode=2;
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{cli(process.argv.slice(2));}
 catch(e){
  const allow=new Set(['USAGE','INPUT_PATH_INVALID','CATALOG_INPUT_INVALID','CATALOG_NUL_BLOCKED',
   'CATALOG_UTF8_INVALID','CATALOG_LINES_INVALID','CATALOG_LINE_INVALID',
   'CATALOG_NOT_SORTED','UNKNOWN_CATALOG_CATEGORY','IDENTICAL_INPUT_PATH']);
  console.log('=== ROTA62 GUARDIAN V5.7 RESTORED CATALOG COMPARISON ===\nSTATUS=BLOCKED_'+
   (allow.has(e.message)?e.message:'REDACTED')+
   '\nDATABASE_CONNECTIONS_OPENED=NO\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

#!/usr/bin/env node
// Guardian V6.4 - read-only PostgreSQL custom archive TOC dependency preflight.
// In-memory companion to authenticated V5.4 pg_restore --list. NO SQL.
// TOC owners are not full global roles; ACL grantees and memberships omitted.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const fail=x=>{throw Error(x);};
const owner=/^(?:-|[a-zA-Z_][a-zA-Z0-9_$-]{0,127})$/;
const TYPES=[
 'DEFAULT ACL','TABLE DATA','FK CONSTRAINT','ROW SECURITY','MATERIALIZED VIEW',
 'SEQUENCE SET','SEQUENCE OWNED BY','PUBLICATION TABLE','PUBLICATION TABLES IN SCHEMA',
 'TABLE ATTACH','INDEX ATTACH','BLOB COMMENTS','LARGE OBJECT','DATABASE PROPERTIES',
 'TABLE','SCHEMA','FUNCTION','PROCEDURE','POLICY','INDEX','TRIGGER','EXTENSION',
 'TYPE','ACL','SEQUENCE','CONSTRAINT','VIEW','COMMENT','PUBLICATION','SUBSCRIPTION',
 'TEXT SEARCH CONFIGURATION','TEXT SEARCH DICTIONARY','TEXT SEARCH PARSER',
 'TEXT SEARCH TEMPLATE','AGGREGATE','DOMAIN','COLLATION','CAST','TRANSFORM',
 'FOREIGN TABLE','FOREIGN DATA WRAPPER','SERVER','USER MAPPING','BLOB'
].sort((a,b)=>b.length-a.length);
export function inspectToc(text,currentMetadata=null){
 if(typeof text!=='string'||Buffer.byteLength(text,'utf8')>16*1024*1024)fail('TOC_SIZE_INVALID');
 const lines=text.split(/\r?\n/),entries=lines.filter(s=>/^\s*\d+;\s+\d+\s+\d+\s+/.test(s));
 if(entries.length<5||entries.length>100000)fail('TOC_ITEMS_INVALID');
 const seen=new Set(),owners=new Set(),ext=new Set();
 let ambiguousOwner=0,extensionEntries=0,unclassifiedEntries=0;
 for(const line of entries){
  const m=/^\s*(\d+);\s+\d+\s+\d+\s+(.+)$/.exec(line);
  if(!m||seen.has(m[1]))fail('TOC_DUPLICATE_ID');
  seen.add(m[1]);
  // pg_restore --list may end ownerless EXTENSION records with a blank
  // owner column, yielding trailing spaces. Normalize only right-edge
  // whitespace; never trim internal names or emit private text.
  const payload=m[2].trimEnd();
  const type=TYPES.find(t=>payload.startsWith(t+' '));
  if(!type){unclassifiedEntries++;continue;}
  // pg_restore --list normally renders EXTENSION as "EXTENSION - name"
  // with NO owner token. Some alternate versions show an owner as a third
  // token. Never misclassify the extension's NAME as a role.
  if(type==='EXTENSION'){
   extensionEntries++;
   const match=/^EXTENSION - ([a-zA-Z_][a-zA-Z_0-9-]{0,127})(?: ([-a-zA-Z_][a-zA-Z_0-9$-]{0,127}))?$/.exec(payload);
   if(!match){unclassifiedEntries++;continue;}
   ext.add(match[1]);
   if(match[2]&&match[2]!=='-'){
    if(owner.test(match[2]))owners.add(match[2]);
    else ambiguousOwner++;
   }
   continue;
  }
  // Most other entries finish with owner, but object types such as
  // extensions are special. This remains a conservative CANDIDATE count,
  // not proof of all owner identities or global grants.
  const last=payload.slice(payload.lastIndexOf(' ')+1);
  if(!owner.test(last)){ambiguousOwner++;continue;}
  if(last!=='-')owners.add(last);
 }
 let metadataCompared=false,missingOwnerRoles=0,missingExtensionNames=0;
 if(currentMetadata!==null){
  if(!currentMetadata||typeof currentMetadata!=='object'||Array.isArray(currentMetadata)||
   currentMetadata.evidence!=='CURRENT_METADATA_NOT_ORIGINAL_BACKUP_PROOF'||
   !Array.isArray(currentMetadata.roles)||!Array.isArray(currentMetadata.extensions))fail('CURRENT_METADATA_INVALID');
  const roleNames=new Set();
  for(const r of currentMetadata.roles){
   if(typeof r?.role!=='string'||!owner.test(r.role))fail('CURRENT_METADATA_INVALID');
   roleNames.add(r.role);
  }
  const extensionNames=new Set();
  for(const e of currentMetadata.extensions){
   if(typeof e?.extension!=='string'||!owner.test(e.extension))fail('CURRENT_METADATA_INVALID');
   extensionNames.add(e.extension);
  }
  metadataCompared=true;
  missingOwnerRoles=[...owners].filter(r=>!roleNames.has(r)).length;
  missingExtensionNames=[...ext].filter(r=>!extensionNames.has(r)).length;
 }
 const digest=crypto.createHash('sha256')
  .update([...owners].sort().join('\n')+'\n--EXT--\n'+[...ext].sort().join('\n'))
  .digest('hex').slice(0,16).toUpperCase();
 return {
  entries:entries.length,distinctVisibleOwnerRoles:owners.size,
  extensionsListed:extensionEntries,distinctExtensions:ext.size,
  unclassifiedEntries,ambiguousOwner,
  comparedToCurrent:metadataCompared,missingOwnerRoles,missingExtensionNames,
  dependencyFingerprint16:digest
 };
}
function readPrivate(file,max){
 if(typeof file!=='string'||!path.isAbsolute(file))fail('USAGE');
 const st=fs.lstatSync(file);
 if(!st.isFile()||st.isSymbolicLink()||st.size<32||st.size>max)fail('PRIVATE_INPUT_INVALID');
 return fs.readFileSync(file,'utf8');
}
function cli(argv){
 if(![2,4].includes(argv.length)||argv[0]!=='--private-toc'||
  (argv.length===4&&argv[2]!=='--current-metadata'))fail('USAGE');
 const toc=readPrivate(argv[1],16*1024*1024);
 let meta=null;
 if(argv.length===4){try{meta=JSON.parse(readPrivate(argv[3],1024*1024));}catch{fail('CURRENT_METADATA_INVALID');}}
 const r=inspectToc(toc,meta);
 console.log(['=== ROTA62 GUARDIAN V6.4 TOC DEPENDENCY PREFLIGHT ===',
  'MODE=LOCAL_READ_ONLY_TOC',
  'TOC_ITEMS='+r.entries,
  'TOC_DISTINCT_VISIBLE_OWNER_ROLES='+r.distinctVisibleOwnerRoles,
  'TOC_EXTENSION_ENTRIES='+r.extensionsListed,
  'TOC_DISTINCT_EXTENSION_NAMES='+r.distinctExtensions,
  'TOC_UNCLASSIFIED_ENTRIES='+r.unclassifiedEntries,
  'TOC_AMBIGUOUS_OWNER_ENTRIES='+r.ambiguousOwner,
  'ROLE_EXTENSION_FINGERPRINT_SHA16='+r.dependencyFingerprint16,
  'CURRENT_METADATA_COMPARED='+(r.comparedToCurrent?'YES':'NO'),
  'OWNERS_ABSENT_FROM_CURRENT_ROSTER='+(r.comparedToCurrent?r.missingOwnerRoles:'NOT_CHECKED'),
  'EXTENSIONS_ABSENT_FROM_CURRENT_ROSTER='+(r.comparedToCurrent?r.missingExtensionNames:'NOT_CHECKED'),
  'CURRENT_ROSTER_IS_NOT_HISTORICAL_GLOBALS=YES',
  'TOC_ACL_GRANTEES_AND_ROLE_MEMBERSHIPS_COMPLETE=NO',
  'SAFE_TO_EXECUTE_CREATE_ROLE=NO',
  'READY_TO_RESTORE_REAL_BACKUP=NO',
  'SQL_EXECUTED=NO','PRODUCTION_TOUCHED=NO','END_REPORT_OK'].join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{cli(process.argv.slice(2));}
 catch(e){
  const known=new Set(['USAGE','TOC_SIZE_INVALID','TOC_ITEMS_INVALID','TOC_DUPLICATE_ID',
   'CURRENT_METADATA_INVALID','PRIVATE_INPUT_INVALID']);
  console.log('=== ROTA62 GUARDIAN V6.4 TOC DEPENDENCY PREFLIGHT ===\nSTATUS=BLOCKED_'+
   (known.has(e.message)?e.message:'REDACTED')+
   '\nSQL_EXECUTED=NO\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

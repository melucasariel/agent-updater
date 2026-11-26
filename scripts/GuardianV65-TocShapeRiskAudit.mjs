#!/usr/bin/env node
// Guardian V6.5: conservative TOC shape risk audit (no restore, no SQL).
// This deliberately DOES NOT infer roles, grants or identities from last tokens.
// Output exposes counts only. Input must originate from authenticated archive.
const TYPES=[
 'DEFAULT ACL','TABLE DATA','FK CONSTRAINT','ROW SECURITY','MATERIALIZED VIEW',
 'SEQUENCE SET','SEQUENCE OWNED BY','PUBLICATION TABLES IN SCHEMA',
 'PUBLICATION TABLE','TABLE ATTACH','INDEX ATTACH','BLOB COMMENTS',
 'LARGE OBJECT','DATABASE PROPERTIES','TEXT SEARCH CONFIGURATION',
 'TEXT SEARCH DICTIONARY','TEXT SEARCH PARSER','TEXT SEARCH TEMPLATE',
 'FOREIGN DATA WRAPPER','FOREIGN TABLE','USER MAPPING',
 'TABLE','SCHEMA','FUNCTION','PROCEDURE','POLICY','INDEX','TRIGGER',
 'EXTENSION','TYPE','ACL','SEQUENCE','CONSTRAINT','VIEW','COMMENT',
 'PUBLICATION','SUBSCRIPTION','AGGREGATE','DOMAIN','COLLATION',
 'CAST','TRANSFORM','SERVER','BLOB'
].sort((a,b)=>b.length-a.length);
const NO_OWNER_PROOF=new Set(['ACL','DEFAULT ACL','COMMENT','SEQUENCE SET',
 'SEQUENCE OWNED BY','TABLE DATA','ROW SECURITY','POLICY','TRIGGER',
 'FK CONSTRAINT','CONSTRAINT','INDEX','EXTENSION','BLOB COMMENTS',
 'DATABASE PROPERTIES','PUBLICATION TABLE','PUBLICATION TABLES IN SCHEMA',
 'TABLE ATTACH','INDEX ATTACH','USER MAPPING']);
export function auditTocShape(toc){
 if(typeof toc!=='string'||Buffer.byteLength(toc,'utf8')>16*1024*1024)throw Error('TOC_SIZE_INVALID');
 const entries=toc.split(/\r?\n/).filter(s=>/^\s*\d+;\s+\d+\s+\d+\s+/.test(s));
 if(entries.length<5||entries.length>100000)throw Error('TOC_ITEMS_INVALID');
 const ids=new Set();
 let known=0, unknown=0, noOwnerProof=0, candidateOnly=0, extension=0;
 let quotedOrNonstandardTail=0;
 for(const line of entries){
  const m=/^\s*(\d+);\s+\d+\s+\d+\s+(.+)$/.exec(line);
  if(!m||ids.has(m[1]))throw Error('TOC_DUPLICATE_ID');
  ids.add(m[1]);
  const payload=m[2].trimEnd();
  const type=TYPES.find(t=>payload.startsWith(t+' '));
  if(!type){unknown++;continue;}
  known++;
  if(type==='EXTENSION'){
   extension++;
   if(!/^EXTENSION - [a-zA-Z_][a-zA-Z_0-9-]{0,127}(?: [-a-zA-Z_][a-zA-Z_0-9$-]{0,127})?$/.test(payload))
    throw Error('EXTENSION_TOC_FORMAT_UNSUPPORTED');
  }
  // Even a syntactically valid last token may be a part of an object name.
  // Never promote these counts to verified owner/global-role evidence.
  if(NO_OWNER_PROOF.has(type))noOwnerProof++;
  else candidateOnly++;
  const tail=payload.slice(payload.lastIndexOf(' ')+1);
  if(!/^(?:-|[a-zA-Z_][a-zA-Z0-9_$-]{0,127})$/.test(tail))
   quotedOrNonstandardTail++;
 }
 return Object.freeze({
  entries:entries.length,recognizedTypes:known,unrecognizedTypes:unknown,
  typesWithoutOwnerProof:noOwnerProof,structuralOwnerCandidatesOnly:candidateOnly,
  nonstandardLastTokens:quotedOrNonstandardTail,extensionEntries:extension,
  verifiedHistoricalGlobalRoles:0,rolesAndAclRestoreReady:false,
  sqlExecuted:false,productionTouched:false
 });
}

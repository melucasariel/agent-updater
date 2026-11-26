#!/usr/bin/env node
// ROTA62 V6.6: diagnostic-only, bounded in-memory classification of TOC blind spots.
// No database access, SQL, credentials, or printing arbitrary TOC content.
// Caller must authenticate encrypted archive before supplying TOC text.
import {auditTocShape} from './GuardianV65-TocShapeRiskAudit.mjs';
// Explicit public pg_dump type labels NOT in V6.5's recognized set.
// Only these fixed type labels are ever returned; object names are discarded.
const PG_KINDS=[
 'STATISTICS DATA','STATISTICS','EVENT TRIGGER','OPERATOR CLASS',
 'OPERATOR FAMILY','OPERATOR','ACCESS METHOD','LANGUAGE',
 'DATABASE','ENCODING','SCHEMA','EXTENSION','TABLE','FUNCTION',
 'PROCEDURAL LANGUAGE','RULE','CONVERSION','TS CONFIGURATION',
 'TS DICTIONARY','TS PARSER','TS TEMPLATE','FOREIGN SERVER',
 'BLOB METADATA','LARGE OBJECT METADATA'
].sort((a,b)=>b.length-a.length);
const KNOWN_BY_V65=new Set(['SCHEMA','EXTENSION','TABLE','FUNCTION']);
const ENTRY=/^\s*(\d+);\s+\d+\s+\d+\s+(.+)$/;
const TYPES_V65=[
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
const safeTail=/^(?:-|[a-zA-Z_][a-zA-Z0-9_$-]{0,127})$/;
export function auditTocBlindSpots(toc){
 const base=auditTocShape(toc);
 let canonicalExtra=0, unknownShape=0;
 let v65Nonstandard=0, nonstandardCandidate=0, nonstandardNoOwnerProof=0;
 const canonicalLabels=Object.create(null);
 const lines=toc.split(/\r?\n/).filter(s=>/^\s*\d+;\s+\d+\s+\d+\s+/.test(s));
 for(const line of lines){
  const m=ENTRY.exec(line);
  if(!m)throw Error('TOC_LINE_INVALID');
  const payload=m[2].trimEnd();
  const type=TYPES_V65.find(t=>payload.startsWith(t+' '));
  if(!type){
   const label=PG_KINDS.find(t=>!KNOWN_BY_V65.has(t)&&payload.startsWith(t+' '));
   if(label){canonicalExtra++;canonicalLabels[label]=(canonicalLabels[label]||0)+1;}
   else unknownShape++;
   continue;
  }
  const tail=payload.slice(payload.lastIndexOf(' ')+1);
  if(!safeTail.test(tail)){
   v65Nonstandard++;
   // Diagnostic distinction only: not verified owner.
   if(NO_OWNER_PROOF.has(type))nonstandardNoOwnerProof++;
   else nonstandardCandidate++;
  }
 }
 if(canonicalExtra+unknownShape!==base.unrecognizedTypes ||
    v65Nonstandard!==base.nonstandardLastTokens)
  throw Error('TOC_AUDIT_MISMATCH');
 return Object.freeze({
  entries:base.entries,
  v65Unrecognized:base.unrecognizedTypes,
  recognizedPublicPgKindsNotInV65:canonicalExtra,
  otherUnknownShapes:unknownShape,
  // Output includes ONLY fixed standard kind names, never user-supplied strings.
  publicKindHistogram:Object.freeze({...canonicalLabels}),
  v65NonstandardLastTokens:v65Nonstandard,
  nonstandardInCandidateOnlyTypes:nonstandardCandidate,
  nonstandardInNoOwnerProofTypes:nonstandardNoOwnerProof,
  historicalRolesVerified:false,restoreReady:false,sqlExecuted:false
 });
}

#!/usr/bin/env node
// ROTA62 V6.7 experimental: aggregated TABLE schema-shape scope only.
// Requires authenticated TOC from caller; no SQL, role, object name, or plaintext output.
// Never equates pg_dump TABLE entries with the live number of user tables.
import {auditTocShape} from './GuardianV65-TocShapeRiskAudit.mjs';
export function auditTableScope(toc){
 const base=auditTocShape(toc);
 let entries=0,publicSchema=0,otherSimpleSchema=0,noSchema=0,complexOrAmbiguousSchema=0;
 let dataEntries=0;
 for(const line of toc.split(/\r?\n/)){
  const m=/^\s*\d+;\s+\d+\s+\d+\s+(.+)$/.exec(line);
  if(!m)continue;
  if(m[1].startsWith('TABLE DATA ')){dataEntries++;continue;}
  if(!m[1].startsWith('TABLE '))continue;
  entries++;
  const rest=m[1].slice('TABLE '.length);
  const first=rest.match(/^(\S+)(?:\s+|$)/)?.[1];
  if(first==='public')publicSchema++;
  else if(first==='-')noSchema++;
  else if(first && /^[a-zA-Z_][a-zA-Z0-9_$]{0,127}$/.test(first))otherSimpleSchema++;
  else complexOrAmbiguousSchema++;
 }
 if(entries>base.entries||dataEntries>base.entries||entries+dataEntries>base.entries)
  throw Error('TOC_TABLE_SCOPE_COUNT_INVALID');
 return Object.freeze({
  catalogItems:base.entries,tableEntries:entries,tableDataEntries:dataEntries,
  publicSchemaTableEntries:publicSchema,otherSimpleSchemaTableEntries:otherSimpleSchema,
  noSchemaTableEntries:noSchema,complexOrAmbiguousSchemaTableEntries:complexOrAmbiguousSchema,
  originalUserTablesValidated:false,tableDataRowsValidated:false,
  historicalRolesVerified:false,sqlExecuted:false,productionTouched:false
 });
}

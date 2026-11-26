#!/usr/bin/env node
// Guardian V6.8: conservative TABLE vs TABLE DATA TOC pairing in authenticated memory.
// Only fixed counters leave this function. No names, IDs, schemas, owners or hashes leave.
import {auditTocShape} from './GuardianV65-TocShapeRiskAudit.mjs';
const SIMPLE=/^([A-Za-z_][A-Za-z_0-9$]{0,127}) ([A-Za-z_][A-Za-z_0-9$]{0,127}) (-|[A-Za-z_][A-Za-z_0-9$-]{0,127})$/;
const MARK=/^\s*\d+;\s+\d+\s+\d+\s+(.+)$/;
export function auditTocTableDataPairs(toc){
 const base=auditTocShape(toc);
 const tables=new Map(),data=new Map();
 let tableEntries=0,dataEntries=0,ambiguousTables=0,ambiguousData=0;
 for(const line of toc.split(/\r?\n/)){
  const m=MARK.exec(line);
  if(!m)continue;
  const payload=m[1].trimEnd();
  let rest,kind;
  if(payload.startsWith('TABLE DATA ')){kind='data';rest=payload.slice(11);dataEntries++;}
  else if(payload.startsWith('TABLE ')){kind='table';rest=payload.slice(6);tableEntries++;}
  else continue;
  const id=SIMPLE.exec(rest);
  if(!id){if(kind==='table')ambiguousTables++;else ambiguousData++;continue;}
  // Exact *text* equality of schema, object and owner token is a conservative
  // consistency check, NOT proof that the named role exists or can be restored.
  // This ephemeral key never leaves this function.
  const key=id[1]+'\u0000'+id[2]+'\u0000'+id[3];
  const map=kind==='table'?tables:data;
  map.set(key,(map.get(key)||0)+1);
 }
 // Traverse the union so duplicate TABLE DATA entries without any TABLE are
 // counted too. Never count an ambiguous or non-unique key as a confirmed pair.
 let paired=0,unpairedSimpleTables=0,unpairedSimpleData=0,duplicateOrNonUnique=0;
 for(const key of new Set([...tables.keys(),...data.keys()])){
  const n=tables.get(key)||0,d=data.get(key)||0;
  if(n===1&&d===1){paired++;continue;}
  unpairedSimpleTables+=n;
  unpairedSimpleData+=d;
  if(n>1||d>1)duplicateOrNonUnique+=n+d;
 }
 if(tableEntries!==paired+unpairedSimpleTables+ambiguousTables||
    dataEntries!==paired+unpairedSimpleData+ambiguousData||
    tableEntries+dataEntries>base.entries||
    duplicateOrNonUnique>unpairedSimpleTables+unpairedSimpleData||
    duplicateOrNonUnique===1)
  throw Error('TOC_TABLE_DATA_PAIR_ARITHMETIC');
 return Object.freeze({
  entries:base.entries,tableEntries,dataEntries,
  structurallyPaired:paired,unpairedSimpleTableEntries:unpairedSimpleTables,
  unpairedSimpleDataEntries:unpairedSimpleData,
  ambiguousTableEntries:ambiguousTables,ambiguousDataEntries:ambiguousData,
  duplicateOrNonUniqueEntries:duplicateOrNonUnique,
  rowCountsVerified:false,allTableDataVerified:false,sqlExecuted:false,productionTouched:false
 });
}

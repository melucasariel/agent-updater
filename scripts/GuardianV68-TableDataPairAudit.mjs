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
 // These disjoint shape buckets reveal reasons WITHOUT revealing identifiers.
 let ambiguousTableQuoted=0,ambiguousTableUnicode=0,ambiguousTableOther=0;
 let tableOnly=0,dataOnly=0,ownerMismatchTables=0,ownerMismatchData=0;
 let nonuniqueTables=0,nonuniqueData=0;
 for(const line of toc.split(/\r?\n/)){
  const m=MARK.exec(line);
  if(!m)continue;
  const payload=m[1].trimEnd();
  let rest,kind;
  if(payload.startsWith('TABLE DATA ')){kind='data';rest=payload.slice(11);dataEntries++;}
  else if(payload.startsWith('TABLE ')){kind='table';rest=payload.slice(6);tableEntries++;}
  else continue;
  const id=SIMPLE.exec(rest);
  if(!id){
   if(kind==='table'){
    ambiguousTables++;
    // Quoting takes priority over Unicode to avoid overlapping counters.
    if(rest.includes('"'))ambiguousTableQuoted++;
    else if(/[^\x20-\x7e]/.test(rest))ambiguousTableUnicode++;
    else ambiguousTableOther++;
   }else ambiguousData++;
   continue;
  }
  // One schema/object pair may have only one owner. Repeated TABLE entries
  // with DIFFERENT owners are still duplicate names and must not match data.
  // Owner text equality is a consistency check, never verified role evidence.
  const key=id[1]+'\u0000'+id[2];
  const map=kind==='table'?tables:data;
  const seen=map.get(key);
  map.set(key,{count:(seen?.count||0)+1,owner:seen?.owner??id[3]});
 }
 // Traverse the union so duplicate TABLE DATA entries without any TABLE are
 // counted too. Never count an ambiguous or non-unique key as a confirmed pair.
 let paired=0,unpairedSimpleTables=0,unpairedSimpleData=0,duplicateOrNonUnique=0;
 for(const key of new Set([...tables.keys(),...data.keys()])){
  const t=tables.get(key),v=data.get(key);
  const n=t?.count||0,d=v?.count||0;
  if(n===1&&d===1&&t.owner===v.owner){paired++;continue;}
  unpairedSimpleTables+=n;
  unpairedSimpleData+=d;
  if(n>1||d>1){
   duplicateOrNonUnique+=n+d;
   nonuniqueTables+=n;
   nonuniqueData+=d;
  }else if(n===1&&d===1){
   // Identical simple schema/object, different owner token: NOT a pair.
   ownerMismatchTables++;
   ownerMismatchData++;
  }else if(n===1&&d===0)tableOnly++;
  else if(n===0&&d===1)dataOnly++;
  else throw Error('TOC_PAIR_GAP_UNEXPECTED');
 }
 if(tableEntries!==paired+unpairedSimpleTables+ambiguousTables||
    dataEntries!==paired+unpairedSimpleData+ambiguousData||
    tableEntries+dataEntries>base.entries||
    duplicateOrNonUnique>unpairedSimpleTables+unpairedSimpleData||
    duplicateOrNonUnique===1||
    ambiguousTables!==ambiguousTableQuoted+ambiguousTableUnicode+ambiguousTableOther||
    unpairedSimpleTables!==tableOnly+ownerMismatchTables+nonuniqueTables||
    unpairedSimpleData!==dataOnly+ownerMismatchData+nonuniqueData||
    duplicateOrNonUnique!==nonuniqueTables+nonuniqueData)
  throw Error('TOC_TABLE_DATA_PAIR_ARITHMETIC');
 return Object.freeze({
  entries:base.entries,tableEntries,dataEntries,
  structurallyPaired:paired,unpairedSimpleTableEntries:unpairedSimpleTables,
  unpairedSimpleDataEntries:unpairedSimpleData,
  ambiguousTableEntries:ambiguousTables,ambiguousDataEntries:ambiguousData,
  duplicateOrNonUniqueEntries:duplicateOrNonUnique,
  ambiguousTableQuoted,ambiguousTableUnicode,ambiguousTableOther,
  simpleTableWithoutData:tableOnly,simpleDataWithoutTable:dataOnly,
  simpleTableOwnerMismatch:ownerMismatchTables,simpleDataOwnerMismatch:ownerMismatchData,
  simpleNonuniqueTables:nonuniqueTables,simpleNonuniqueData:nonuniqueData,
  rowCountsVerified:false,allTableDataVerified:false,sqlExecuted:false,productionTouched:false
 });
}

#!/usr/bin/env node
// Guardian V6.8: conservative TABLE vs TABLE DATA TOC pairing in authenticated memory.
// Only fixed counters leave this function. No names, IDs, schemas, owners or hashes leave.
import {auditTocShape} from './GuardianV65-TocShapeRiskAudit.mjs';
const SIMPLE=/^([A-Za-z_][A-Za-z_0-9$]{0,127}) ([A-Za-z_][A-Za-z_0-9$]{0,127}) (-|[A-Za-z_][A-Za-z_0-9$-]{0,127})$/;
const MARK=/^\s*\d+;\s+\d+\s+\d+\s+(.+)$/;
export function auditTocTableDataPairs(toc){
 const base=auditTocShape(toc);
 const tables=new Map(),data=new Map();
 const oidTables=new Map(),oidData=new Map();
 let oidInvalidTable=0,oidInvalidData=0;
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
  // The third numeric field is the object's OID; TABLE uses catalog class
  // 1259 and TABLE DATA normally uses class 0. Verify exact class and
  // nonzero 32-bit OID before considering an independent metadata match.
  const oidLine=/^\s*\d+;\s+(\d+)\s+(\d+)\s+/.exec(line);
  const expectedClass=kind==='table'?'1259':'0';
  const oid=oidLine?.[2];
  const validOid=oidLine?.[1]===expectedClass&&
    /^(?:[1-9][0-9]*)$/.test(oid||'')&&
    Number(oid)<=4294967295;
  if(validOid){
   const target=kind==='table'?oidTables:oidData;
   target.set(oid,(target.get(oid)||0)+1);
  }else if(kind==='table')oidInvalidTable++;
  else oidInvalidData++;
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
 let oidPaired=0,oidOnlyTable=0,oidOnlyData=0,oidDuplicateTable=0,oidDuplicateData=0;
 for(const oid of new Set([...oidTables.keys(),...oidData.keys()])){
  const t=oidTables.get(oid)||0,d=oidData.get(oid)||0;
  if(t===1&&d===1){oidPaired++;continue;}
  if(t>1||d>1){oidDuplicateTable+=t;oidDuplicateData+=d;}
  else if(t===1&&d===0)oidOnlyTable++;
  else if(t===0&&d===1)oidOnlyData++;
  else throw Error('TOC_OID_COUNTER_UNEXPECTED');
 }
 if(tableEntries!==paired+unpairedSimpleTables+ambiguousTables||
    dataEntries!==paired+unpairedSimpleData+ambiguousData||
    tableEntries+dataEntries>base.entries||
    duplicateOrNonUnique>unpairedSimpleTables+unpairedSimpleData||
    duplicateOrNonUnique===1||
    ambiguousTables!==ambiguousTableQuoted+ambiguousTableUnicode+ambiguousTableOther||
    unpairedSimpleTables!==tableOnly+ownerMismatchTables+nonuniqueTables||
    unpairedSimpleData!==dataOnly+ownerMismatchData+nonuniqueData||
    duplicateOrNonUnique!==nonuniqueTables+nonuniqueData||
    tableEntries!==oidPaired+oidOnlyTable+oidDuplicateTable+oidInvalidTable||
    dataEntries!==oidPaired+oidOnlyData+oidDuplicateData+oidInvalidData)
  throw Error('TOC_TABLE_DATA_PAIR_ARITHMETIC');
 return Object.freeze({
  entries:base.entries,tableEntries,dataEntries,
  structurallyPaired:paired,unpairedSimpleTableEntries:unpairedSimpleTables,
  unpairedSimpleDataEntries:unpairedSimpleData,
  ambiguousTableEntries:ambiguousTables,ambiguousDataEntries:ambiguousData,
  duplicateOrNonUniqueEntries:duplicateOrNonUnique,
  oidStructurallyMatched:oidPaired,
  oidTableOnly:oidOnlyTable,oidDataOnly:oidOnlyData,
  oidDuplicateTable,oidDuplicateData,oidInvalidTable,oidInvalidData,
  ambiguousTableQuoted,ambiguousTableUnicode,ambiguousTableOther,
  simpleTableWithoutData:tableOnly,simpleDataWithoutTable:dataOnly,
  simpleTableOwnerMismatch:ownerMismatchTables,simpleDataOwnerMismatch:ownerMismatchData,
  simpleNonuniqueTables:nonuniqueTables,simpleNonuniqueData:nonuniqueData,
  rowCountsVerified:false,allTableDataVerified:false,sqlExecuted:false,productionTouched:false
 });
}

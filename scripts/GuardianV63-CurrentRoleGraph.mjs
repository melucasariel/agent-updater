#!/usr/bin/env node
// Guardian V6.3 — strictly read-only analysis of CURRENT PostgreSQL role grants
// and owner/default-ACL distribution (not a historical globals backup).
// Never prints role names or paths, never generates/replays CREATE ROLE or GRANT.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {fileURLToPath} from 'node:url';
const fail=code=>{throw Error(code);};
const ident=s=>typeof s==='string'&&/^[a-zA-Z_][a-zA-Z_0-9$-]{0,100}$/.test(s);
const exact=(x,fields)=>{if(!x||typeof x!=='object'||Array.isArray(x)||Object.keys(x).sort().join('|')!==fields.slice().sort().join('|'))fail('UNEXPECTED_REPORT_FIELD');};
const positive=x=>Number.isSafeInteger(x)&&x>0&&x<1e8;
export function inspectCurrentRoleGraph(report){
 exact(report,['evidence','default_acls','object_owners','role_memberships']);
 if(report.evidence!=='CURRENT_METADATA_ONLY'||!Array.isArray(report.role_memberships)||
  !Array.isArray(report.object_owners)||!Array.isArray(report.default_acls)||
  report.role_memberships.length>10000||report.object_owners.length>10000||
  report.default_acls.length>10000)fail('INVALID_CURRENT_METADATA');
 const edges=new Set(),memberDetails=[],graph=new Map(),memberRoles=new Set();
 let admin=0,inherit=0,set=0,selfGrants=0;
 for(const m of report.role_memberships){
  exact(m,['granted_role','member_role','admin_option','inherit_option','set_option']);
  if(!ident(m.granted_role)||!ident(m.member_role)||
   typeof m.admin_option!=='boolean'||typeof m.inherit_option!=='boolean'||
   typeof m.set_option!=='boolean')fail('INVALID_ROLE_GRANT');
  const k=m.granted_role+'\0'+m.member_role;
  if(edges.has(k))fail('DUPLICATE_MEMBERSHIP');
  edges.add(k);memberRoles.add(m.granted_role);memberRoles.add(m.member_role);
  memberDetails.push([m.granted_role,m.member_role,m.admin_option,m.inherit_option,m.set_option]);
  admin+=Number(m.admin_option);inherit+=Number(m.inherit_option);set+=Number(m.set_option);
  if(m.granted_role===m.member_role)selfGrants++;
  const n=graph.get(m.member_role)||[];n.push(m.granted_role);graph.set(m.member_role,n);
 }
 // Detect graph cycles without executing any role SQL.
 const visited=new Set(),active=new Set();
 let cyclic=false;
 function visit(role){
  if(active.has(role)){cyclic=true;return;}
  if(visited.has(role))return;
  active.add(role);
  for(const to of graph.get(role)||[])visit(to);
  active.delete(role);visited.add(role);
 }
 for(const role of memberRoles)visit(role);
 const ownerGroups=new Set(),ownerDetails=[],ownerRoles=new Set(),ownerSchemas=new Set();
 let objectCount=0;
 for(const r of report.object_owners){
  exact(r,['owner_role','schema_name','object_count']);
  if(!ident(r.owner_role)||!ident(r.schema_name)||!positive(r.object_count))fail('INVALID_OWNER_GROUP');
  const k=r.schema_name+'\0'+r.owner_role;
  if(ownerGroups.has(k))fail('DUPLICATE_OWNER_GROUP');
  ownerGroups.add(k);ownerRoles.add(r.owner_role);ownerSchemas.add(r.schema_name);
  ownerDetails.push([r.schema_name,r.owner_role,r.object_count]);
  objectCount+=r.object_count;
 }
 const defaultEntries=new Set(),aclDetails=[],defaultSchemas=new Set(),defaultRoles=new Set();
 let aclCount=0;
 for(const d of report.default_acls){
  exact(d,['entries','owner_role','object_type','schema_name']);
  if(!ident(d.owner_role)||!ident(d.schema_name)||!['S','f','r','T','n'].includes(d.object_type)||
   !positive(d.entries))fail('INVALID_DEFAULT_ACL_GROUP');
  const k=d.owner_role+'\0'+d.schema_name+'\0'+d.object_type;
  if(defaultEntries.has(k))fail('DUPLICATE_DEFAULT_ACL_GROUP');
  defaultEntries.add(k);defaultSchemas.add(d.schema_name);defaultRoles.add(d.owner_role);
  aclDetails.push([d.owner_role,d.schema_name,d.object_type,d.entries]);
  aclCount+=d.entries;
 }
 const digest=crypto.createHash('sha256').update(JSON.stringify({
  memberships:memberDetails.map(x=>JSON.stringify(x)).sort(),
  owners:ownerDetails.map(x=>JSON.stringify(x)).sort(),
  acl:aclDetails.map(x=>JSON.stringify(x)).sort(),count:objectCount,aclCount
 })).digest('hex').slice(0,16).toUpperCase();
 return {membershipEdges:edges.size,distinctMembershipRoles:memberRoles.size,admin,inherit,set,
  selfGrants,cyclic,objectGroups:ownerGroups.size,objectSchemas:ownerSchemas.size,
  ownerRoles:ownerRoles.size,objectCount,defaultAclCount:aclCount,
  defaultAclGroups:defaultEntries.size,defaultAclSchemas:defaultSchemas.size,
  defaultAclRoles:defaultRoles.size,summaryFingerprint16:digest};
}
function cli(args){
 if(args.length!==2||args[0]!=='--current-role-graph'||!path.isAbsolute(args[1]))fail('USAGE');
 const st=fs.lstatSync(args[1]);
 if(!st.isFile()||st.isSymbolicLink()||st.size>1024*1024||st.size<20)fail('INPUT_INVALID');
 let obj;try{obj=JSON.parse(fs.readFileSync(args[1],'utf8'));}catch{fail('JSON_INVALID');}
 const r=inspectCurrentRoleGraph(obj);
 console.log(['=== ROTA62 GUARDIAN V6.3 CURRENT ROLE GRAPH ===',
  'CURRENT_ROLE_MEMBERSHIPS='+r.membershipEdges,
  'CURRENT_ROLE_MEMBERSHIP_NODES='+r.distinctMembershipRoles,
  'CURRENT_ADMIN_OPTION_GRANTS='+r.admin,
  'CURRENT_INHERIT_OPTION_GRANTS='+r.inherit,
  'CURRENT_SET_OPTION_GRANTS='+r.set,
  'SELF_GRANTS_DETECTED='+r.selfGrants,
  'MEMBERSHIP_CYCLE_DETECTED='+(r.cyclic?'YES':'NO'),
  'CURRENT_PG_CLASS_OWNER_GROUPS='+r.objectGroups,
  'CURRENT_PG_CLASS_OBJECT_COUNT='+r.objectCount,
  'CURRENT_PG_CLASS_SCHEMAS='+r.objectSchemas,
  'CURRENT_DISTINCT_OBJECT_OWNER_ROLES='+r.ownerRoles,
  'CURRENT_DEFAULT_ACL_GROUPS='+r.defaultAclGroups,
  'CURRENT_DEFAULT_ACL_ENTRIES='+r.defaultAclCount,
  'CURRENT_DEFAULT_ACL_SCHEMAS='+r.defaultAclSchemas,
  'CURRENT_ROLE_GRAPH_FINGERPRINT_SHA16='+r.summaryFingerprint16,
  'PG_CLASS_OBJECTS_ARE_NOT_TABLE_COUNT=YES',
  'HISTORICAL_ROLES_FROM_BACKUP_PROVEN=NO',
  'GLOBAL_ROLE_REPLAY_AUTHORIZED=NO',
  'SQL_EXECUTED=NO','PRODUCTION_TOUCHED=NO','END_REPORT_OK'].join('\n'));
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{cli(process.argv.slice(2));}
 catch(e){
  const safe=new Set(['USAGE','INPUT_INVALID','JSON_INVALID','INVALID_CURRENT_METADATA',
   'INVALID_ROLE_GRANT','DUPLICATE_MEMBERSHIP','INVALID_OWNER_GROUP','DUPLICATE_OWNER_GROUP',
   'INVALID_DEFAULT_ACL_GROUP','DUPLICATE_DEFAULT_ACL_GROUP','UNEXPECTED_REPORT_FIELD']);
  console.log('=== ROTA62 GUARDIAN V6.3 CURRENT ROLE GRAPH ===\nSTATUS=BLOCKED_'+
   (safe.has(e.message)?e.message:'REDACTED')+
   '\nSQL_EXECUTED=NO\nPRODUCTION_TOUCHED=NO\nEND_REPORT_OK');
  process.exitCode=2;
 }
}

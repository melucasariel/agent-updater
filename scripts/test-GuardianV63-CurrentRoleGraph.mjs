import assert from 'node:assert/strict';
import {inspectCurrentRoleGraph} from './GuardianV63-CurrentRoleGraph.mjs';
const r={
 evidence:'CURRENT_METADATA_ONLY',
 role_memberships:[
  {granted_role:'anon',member_role:'authenticator',admin_option:false,inherit_option:false,set_option:true},
  {granted_role:'service_role',member_role:'postgres',admin_option:true,inherit_option:true,set_option:true},
  {granted_role:'pg_monitor',member_role:'supabase_admin',admin_option:false,inherit_option:true,set_option:true}
 ],
 object_owners:[
  {schema_name:'public',owner_role:'postgres',object_count:79},
  {schema_name:'auth',owner_role:'supabase_auth_admin',object_count:140}
 ],
 default_acls:[
  {owner_role:'postgres',schema_name:'public',object_type:'r',entries:1},
  {owner_role:'postgres',schema_name:'public',object_type:'f',entries:1}
 ]
};
const valid=inspectCurrentRoleGraph(r);
assert.equal(valid.membershipEdges,3);assert.equal(valid.admin,1);
assert.equal(valid.objectCount,219);assert.equal(valid.objectGroups,2);
assert.equal(valid.defaultAclCount,2);
assert.equal(valid.cyclic,false);
const changed={...r,role_memberships:[...r.role_memberships,r.role_memberships[0]]};
assert.throws(()=>inspectCurrentRoleGraph(changed),e=>e.message==='DUPLICATE_MEMBERSHIP');
const bad={...r,object_owners:[...r.object_owners,{...r.object_owners[0]}]};
assert.throws(()=>inspectCurrentRoleGraph(bad),e=>e.message==='DUPLICATE_OWNER_GROUP');
const leaked={...r,secrets:'private'};
assert.throws(()=>inspectCurrentRoleGraph(leaked),e=>e.message==='UNEXPECTED_REPORT_FIELD');
const cycle={...r,role_memberships:[
 {granted_role:'a',member_role:'b',admin_option:false,inherit_option:true,set_option:true},
 {granted_role:'b',member_role:'a',admin_option:false,inherit_option:true,set_option:true}
]};
assert.equal(inspectCurrentRoleGraph(cycle).cyclic,true);
console.log('V63_CURRENT_ROLE_MEMBERSHIP_COUNTS=PASS');
console.log('V63_DUPLICATE_ROLE_GRANTS_AND_OBJECT_OWNERS=BLOCKED');
console.log('V63_MEMBERSHIP_CYCLE_DETECTION=PASS');
console.log('V63_HISTORICAL_BACKUP_ROLE_REPLAY=NOT_AUTHORIZED');
console.log('V63_SQL_EXECUTED=NO');

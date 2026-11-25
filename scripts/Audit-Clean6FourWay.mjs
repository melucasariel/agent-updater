#!/usr/bin/env node
// ROTA62 CLEAN6 — Four-way catalog audit; never writes PostgreSQL, Docker, or files.
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';

const CURRENT=fileURLToPath(import.meta.url);
const PGOPT='PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=2000';
const fail=(code)=>{throw Error(code);};
const exec=(args,input)=>{
  const r=spawnSync('docker',args,{encoding:'utf8',input,timeout:30000,maxBuffer:8*1024*1024,windowsHide:true});
  if(r.error||r.status!==0||typeof r.stdout!=='string')fail('DOCKER_FAILED');
  return r.stdout.trim();
};
const sqlRun=(id,db,sql)=>{
  if(!/^[a-zA-Z_][\w]{0,62}$/.test(db))fail('INVALID_DB_NAME');
  return exec(['exec','-i','--user','postgres','-e',PGOPT,id,'psql','-X','-qAt','-w','-U','postgres','-d',db,'-v','ON_ERROR_STOP=1','-f','-'],sql);
};
const check=(id)=>{
  const v=JSON.parse(exec(['inspect',id]));
  if(v.length!==1)fail('BAD_INSPECT');
  const c=v[0];
  if(!c.State?.Running||!c.Id?.startsWith(id))fail('NOT_RUNNING');
  if(!String(c.Config?.Image).toLowerCase().includes('postgres'))fail('NOT_POSTGRES');
  if(c.Mounts?.length!==1||c.Mounts[0].Type!=='volume')fail('BAD_STORAGE');
  const nets=Object.keys(c.NetworkSettings?.Networks||{});
  if(nets.length!==1||c.HostConfig?.NetworkMode==='host')fail('BAD_NETWORK');
  const n=JSON.parse(exec(['network','inspect',nets[0]]));
  if(n.length!==1||n[0].Internal!==true)fail('NOT_INTERNAL');
  for(const v of Object.values(c.NetworkSettings?.Ports||{}))if(Array.isArray(v)&&v.length)fail('PORT_PUBLISHED');
  for(const v of Object.values(c.HostConfig?.PortBindings||{}))if(Array.isArray(v)&&v.length)fail('PORT_PUBLISHED');
};
function canon(m){
  if(m?.format!=='r62-clean6-semantic-v1'||!Array.isArray(m.owners)||!Array.isArray(m.acls))fail('BAD_MANIFEST');
  if(m.owners.length>20000||m.acls.length>100000)fail('OVERSIZE');
  const owners=new Map(),acls=new Map();
  for(const x of m.owners){
    if(typeof x?.id!=='string'||!x.id||typeof x.owner!=='string'||!x.owner||owners.has(x.id))fail('BAD_OWNER');
    owners.set(x.id,x.owner);
  }
  for(const x of m.acls){
    if(!x||['id','grantee','privilege','grantor'].some(k=>typeof x[k]!=='string'||!x[k])||typeof x.grantable!=='boolean')fail('BAD_ACL');
    const key=JSON.stringify([x.id,x.grantee,x.privilege,x.grantor,x.grantable]);
    if(acls.has(key))fail('DUPLICATE_ACL');
    acls.set(key,x.id);
  }
  const hash=createHash('sha256').update(JSON.stringify([[...owners].sort((a,b)=>a[0].localeCompare(b[0])),[...acls.keys()].sort()])).digest('hex').slice(0,16).toUpperCase();
  return {owners,acls,hash};
}
const typ=id=>id.startsWith('schema:')?'SCHEMA':id.startsWith('relation:')?'RELATION':id.startsWith('function:')?'FUNCTION':id.startsWith('type:')?'TYPE':id.startsWith('defaultacl:')?'DEFAULT_ACL':'OTHER';
export function compare(a,b){
  const byType={};let changed=0,missing=0,added=0,removedAcl=0,addedAcl=0;
  const hit=k=>{byType[k]=(byType[k]||0)+1;};
  for(const [id,owner] of a.owners){
    if(!b.owners.has(id)){missing++;hit('OWNER_'+typ(id));}
    else if(owner!==b.owners.get(id)){changed++;hit('OWNER_'+typ(id));}
  }
  for(const id of b.owners.keys())if(!a.owners.has(id)){added++;hit('OWNER_'+typ(id));}
  for(const [k,id] of a.acls)if(!b.acls.has(k)){removedAcl++;hit('ACL_'+typ(id));}
  for(const [k,id] of b.acls)if(!a.acls.has(k)){addedAcl++;hit('ACL_'+typ(id));}
  return {changed,missing,added,removedAcl,addedAcl,byType,total:changed+missing+added+removedAcl+addedAcl};
}
function snapshot(id,sql,tables,extensions){
  const names=exec(['exec','--user','postgres','-e',PGOPT,id,'psql','-X','-qAt','-w','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-c','SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY datname LIMIT 10']).split(/\r?\n/).filter(Boolean);
  const found=[];
  const stat="BEGIN READ ONLY; SELECT current_setting('server_version_num')||'|'||(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname<>'information_schema' AND n.nspname!~'^pg_')||'|'||(SELECT count(*) FROM pg_extension WHERE extname<>'plpgsql'); ROLLBACK;";
  for(const db of names){
    const result=sqlRun(id,db,stat);
    const m=result.match(/^(\d+)\|(\d+)\|(\d+)$/m);
    if(!m)fail('BAD_STATS');
    if(Number(m[1])>=170000&&Number(m[1])<180000&&Number(m[2])===tables&&Number(m[3])===extensions)found.push(db);
  }
  if(found.length!==1)fail('AMBIGUOUS_DB');
  let m;try{m=JSON.parse(sqlRun(id,found[0],sql));}catch{fail('BAD_JSON');}
  return canon(m);
}
function argumentsFor(argv){
  const args={};
  if(argv.length%2!==0||argv.length===0)fail('USAGE');
  for(let i=0;i<argv.length;i+=2){
    if(!['--containers','--reference','--expected-tables','--expected-extensions'].includes(argv[i])||argv[i] in args)fail('USAGE');
    args[argv[i]]=argv[i+1];
  }
  const ids=String(args['--containers']||'').split(',');
  if(ids.length<1||ids.length>8||ids.some(x=>!/^[a-f0-9]{12,64}$/.test(x))||new Set(ids).size!==ids.length)fail('BAD_IDS');
  if(!ids.includes(args['--reference']))fail('BAD_REFERENCE');
  const nums=[args['--expected-tables']??'76',args['--expected-extensions']??'6'];
  if(nums.some(x=>!/^\d{1,4}$/.test(x)))fail('BAD_COUNTS');
  return {ids,ref:args['--reference'],tables:+nums[0],extensions:+nums[1]};
}
export function main(argv){
  const {ids,ref,tables,extensions}=argumentsFor(argv);
  const sql=readFileSync(join(dirname(CURRENT),'Export-Clean6Catalog.sql'),'utf8');
  if(!sql.includes('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;')||!sql.includes('ROLLBACK;'))fail('UNTRUSTED_SQL');
  const result=[],reports=['=== ROTA62 CLEAN6 FOUR WAY GUARD V1 ===','MODE=READ_ONLY_DOUBLE_SNAPSHOT','REFERENCE_PROVISIONAL=YES'];
  for(const id of ids){
    try{
      check(id);
      const a=snapshot(id,sql,tables,extensions);
      const b=snapshot(id,sql,tables,extensions);
      if(a.hash!==b.hash)fail('CATALOG_DRIFT');
      result.push({id,manifest:a});
      reports.push('PG_'+id+'_STATUS=READ_ONLY_OK');
      reports.push('PG_'+id+'_OWNERS='+a.owners.size);
      reports.push('PG_'+id+'_ACLS='+a.acls.size);
      reports.push('PG_'+id+'_SHA16='+a.hash);
    }catch(e){
      const allowed=['BAD_INSPECT','NOT_RUNNING','NOT_POSTGRES','BAD_STORAGE','BAD_NETWORK','NOT_INTERNAL','PORT_PUBLISHED','BAD_STATS','AMBIGUOUS_DB','BAD_JSON','BAD_MANIFEST','BAD_OWNER','BAD_ACL','DUPLICATE_ACL','CATALOG_DRIFT','DOCKER_FAILED','INVALID_DB_NAME','OVERSIZE'];
      reports.push('PG_'+id+'_STATUS=BLOCKED_'+(allowed.includes(e.message)?e.message:'ERROR_REDACTED'));
    }
  }
  const baseline=result.find(x=>x.id===ref);
  if(baseline)for(const x of result){
    const d=compare(baseline.manifest,x.manifest);
    reports.push('PG_'+x.id+'_DIFFERENCES='+d.total);
    reports.push('PG_'+x.id+'_OWNER_CHANGED='+d.changed);
    reports.push('PG_'+x.id+'_OWNER_MISSING='+d.missing);
    reports.push('PG_'+x.id+'_OWNER_EXTRA='+d.added);
    reports.push('PG_'+x.id+'_ACL_MISSING='+d.removedAcl);
    reports.push('PG_'+x.id+'_ACL_EXTRA='+d.addedAcl);
    for(const [k,v] of Object.entries(d.byType).sort((a,b)=>a[0].localeCompare(b[0])))reports.push('PG_'+x.id+'_'+k+'_DIFFERENCES='+v);
  }
  reports.push('CONTAINERS_AUDITED='+result.length);
  reports.push('BACKUP_PROVENANCE_VERIFIED=NO');
  reports.push('REAL_BACKUP_RECOVERY_VERIFIED=NO');
  reports.push('SQL_WRITES_EXECUTED=NO');
  reports.push('USER_ROWS_QUERIED=NO');
  reports.push('CATALOG_DATA_NOT_SAVED=YES');
  reports.push('END_REPORT_OK');
  process.stdout.write(reports.join('\n')+'\n');
  if(!baseline||result.length!==ids.length)process.exitCode=2;
}
if(process.argv[1]&&resolve(process.argv[1])===CURRENT){
  try{main(process.argv.slice(2));}
  catch(e){
    process.stdout.write('STATUS=BLOCKED\nCODE='+(['USAGE','BAD_IDS','BAD_REFERENCE','BAD_COUNTS','UNTRUSTED_SQL'].includes(e.message)?e.message:'ERROR_REDACTED')+'\nEND_REPORT_OK\n');
    process.exitCode=2;
  }
}

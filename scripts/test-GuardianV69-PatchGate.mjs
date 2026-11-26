#!/usr/bin/env node
import assert from 'node:assert/strict';
import {verifyPg17PatchVersion} from './GuardianV54-ArchiveCatalog.mjs';

for(const ok of ['pg_restore (PostgreSQL) 17.12','pg_restore (PostgreSQL) 17.13','pg_restore (PostgreSQL) 17.99'])
 assert.equal(verifyPg17PatchVersion(ok),true);
for(const unsafe of [null,'','17.12','pg_restore (PostgreSQL) 17.11',
 'pg_restore (PostgreSQL) 17.10','pg_restore (PostgreSQL) 17.9',
 'pg_restore (PostgreSQL) 18.7','pg_restore (PostgreSQL) 16.16',
 'pg_restore (PostgreSQL) 17.120-malformed'])
 assert.throws(()=>verifyPg17PatchVersion(unsafe),e=>e.message==='PG17_PATCH_LEVEL_BLOCKED');
console.log('V69_DEEP_READ_MINIMUM_PG17_12_FAIL_CLOSED=PASS');
console.log('V69_NO_IMAGE_DOWNLOAD_NO_PRODUCTION=YES');

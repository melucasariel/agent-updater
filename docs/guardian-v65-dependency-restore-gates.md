# ROTA62 Guardian V6.5 — Gates de dependências antes de qualquer restore

Data da evidência local: 2026-11-25. Escopo: **somente planejamento e verificações de leitura**. Nenhuma recuperação foi autorizada.

## Evidência autenticada do backup TaxiRadar
Relatório do operador Windows V5.4 com parser V6.4.2 (commit `b56dec1c9299e86c53448cfe1efb3e643fd87ea9`):
- Três cópias do mesmo ciphertext SHA-256; autenticação AES-GCM = YES; pg_restore custom PG17 catalog = PASS.
- Itens TOC = 919; EXTENSION entries = 6 e **nomes distintos reconhecidos = 6**.
- Visible owner role **candidates** = 12, unclassified entries = 9, ambiguous owner entries = 1.
- Fingerprint de dependências truncado `D64BAAF7FE446D60` (não substitui identidades históricas).
- SQL executado = NO; produção tocada = NO; plaintext persistido = NO.
- `TOC_TABLE=77` vs referência histórica 76 tabelas de usuário: **não declarar erro nem equivalência sem investigar escopo**.

## Limite crítico do parser
`GuardianV64-TocDependencyPreflight.mjs` coleta, para quase todos os tipos exceto EXTENSION, o último token do payload se parecer com um identificador. Isso pode identificar incorretamente uma palavra de objeto como owner. Portanto **12 candidatos não são prova de 12 roles**, e o inventário não é base autorizada para gerar `CREATE ROLE`, `GRANT` ou `ALTER OWNER`.
As 9 entradas não classificadas podem ser tipos de TOC sem proprietário (ex.: metadados), e 1 proprietário ambíguo pode refletir nome com espaços/aspas. Não pressupor criticidade, nem ignorá-los.

## Gates obrigatórios antes do restore real
1. **GATE-A (catalog parser)**: classificar entradas restantes por tipo, conservando apenas contagens/redactions. Fixtures adversariais cobrindo objetos com nome final que parece owner, nomes citados, espaços, ACL/DEFAULT ACL. Erros de classificação devem falhar fechados para decisão de restore, sem impedir diagnóstico seguro.
2. **GATE-B (historical globals)**: obter prova autenticada independente das roles do momento do snapshot: atributos, membership, owners, grantees, default privileges. Metadados do Supabase atual são referência de comparação, nunca prova histórica.
3. **GATE-C (extensions)**: comparar **nomes e versões** requeridas pelo dump versus disponibilidade do ambiente PG17 de destino, com consistência e compatibilidade; 6/6 nomes extraídos não provam presença no destino.
4. **GATE-D (isolated restore)**: criar PostgreSQL 17 compatível em destino novo e descartável, rede externa bloqueada, pg_cron/pg_net e quaisquer tarefas externas desativadas. Nunca reutilizar CLEAN6. Restaurar preservando owners/ACLs (não usar `--no-owner` ou `--no-privileges` para declarar fidelidade).
5. **GATE-E (integridade)**: checar erros do restore, tabelas e linhas de dados, constraints, triggers, RLS, policies, functions, sequences, grants, owners e compare com inventário do backup; 77 vs 76 deve ser explicado pelo escopo.
6. **GATE-F (DR completo)**: confirmar Web, API, Storage **com conteúdo real**, secrets e endpoints, push, backups e DNS; medir RTO ponta-a-ponta. Até lá `RTO_4_TO_6_HOURS_PROVEN=NO`.

## Guardrails
- Backup imutável; senha digitada somente em terminal local, nunca em log/clipboard.
- Comandos diagnósticos: uma execução, logs **sanitizados** com Set-Clipboard, sem SQL modificador e sem tocar produção.
- Nenhum deploy automático, PR continua draft, sem atualização do agente em operação.
- Backups manuais antes das alterações, não job a cada quatro horas.
- Próxima implementação proposta: aprimorar a classificação de owners e produzir **contagens por classe de ambiguidade**; validar em CI com PG17 sintético antes de repetir qualquer operação no backup real.

## Implementação experimental V6.5 — auditor separado
- `scripts/GuardianV65-TocShapeRiskAudit.mjs` faz classificação de formato **somente em memória**. Não emite nomes de objetos, roles ou extensões, não executa SQL e não reivindica propriedade histórica.
- `scripts/test-GuardianV65-TocShapeRiskAudit.mjs` cobre colunas vazias de extensão, tipos desconhecidos, identificadores com aspas, IDs duplicados e impedimento explícito de inferir roles verificadas.
- A pipeline `guardian-v54-catalog.yml` inclui os testes V6.5 junto ao dump sintético PG17; não lê o backup real em CI.
- **Histórico:** inicialmente o auditor foi independente. Consultar a seção de integração abaixo para o estado mais recente.
- **Atenção às métricas:** `typesWithoutOwnerProof` conta entradas cujo *tipo* não autoriza inferir proprietário, e não prova que essas entradas não tenham proprietário no PostgreSQL. `structuralOwnerCandidatesOnly` também não representa roles reais.

## V6.5 report integration — pending new CI result
- V5.4 authenticating catalog now imports `GuardianV65-TocShapeRiskAudit.mjs`, verifies equal TOC entry totals and extension-entry totals against V6.4, and emits safe `SHAPE_*` counters. The V6.4 parser and archive cryptographic flow remain unchanged.
- V5.5 strict report parser recognizes optional `SHAPE_*` fields (backwards compatible), enforces `recognized+unrecognized=archive items`, `no-owner-proof+candidate-only=recognized`, and `nonstandard<=recognized`. It never sums `SHAPE_*` fields into `TOC_*` totals.
- Windows operator now **requires five local scripts**, including the new V6.5 module, before asking for the password. Any future run must pin and SHA-check all five files from the same CI-reviewed commit; old 4-file command is NOT compatible with the updated importer.
- V6.5 additional metrics are classification-only, NOT historical roles proof, permissions inventory, or restore permission.
- These modifications require **fresh commit-specific CI success** before execution against the real encrypted archive.

## Evidência real V6.5 — catálogo autenticado, sem restauração (2026-11-25)
Execução local pelo operador, após CI 34/34 no commit `32f338b4bcd4f5d4a0fdde5bc06fc02d1a7bb8e2`:
- `ARCHIVES_CHECKED=3`, `MATCHING_CIPHERTEXT_COPIES=3`.
- `CIPHERTEXT_SHA256_MATCH=YES`, `AES_GCM_TAG_AUTHENTICATED=YES`, `PG_RESTORE_CATALOG=PASS`.
- `ARCHIVE_CONTENT_SHA16=EA995E37864FF769`; `ARCHIVE_CATALOG_ITEMS=919`.
- `DEPENDENCY_VISIBLE_OWNER_ROLES=12` (apenas candidatos), `DEPENDENCY_DISTINCT_EXTENSIONS=6`, `DEPENDENCY_UNCLASSIFIED_TOC_ENTRIES=9`, `DEPENDENCY_AMBIGUOUS_TOC_OWNER_ENTRIES=1`, `DEPENDENCY_SHA16=D64BAAF7FE446D60`.
- `SHAPE_RECOGNIZED_TYPES=910`; `SHAPE_UNRECOGNIZED_TYPES=9`; `SHAPE_NO_OWNER_PROOF_ITEMS=724`; `SHAPE_OWNER_CANDIDATE_ONLY_ITEMS=186`; `SHAPE_NONSTANDARD_LAST_TOKENS=1`; `SHAPE_HISTORICAL_GLOBAL_ROLES_VERIFIED=NO`.
- Cross-checks: 910+9=919; 724+186=910; `TOC_EXTENSION=6`.
- `PG_RESTORE_EXECUTED_SQL=NO`, `DATABASE_RESTORED=NO`, `ARCHIVE_PLAINTEXT_FILE_WRITTEN=NO`, `PRODUCTION_TOUCHED=NO`, `RTO_4_TO_6_HOURS_PROVEN=NO`.

### Interpretação e próximo gate
Esses indicadores são **evidência do relatório local fornecido pelo operador**, não logs da própria CI, nem prova de dados, owners ou grants restaurados. As nove entradas não reconhecidas e um token final não padronizado ainda exigem classificação segura em memória. `TOC_OTHER=13` tem definição distinta de `SHAPE_UNRECOGNIZED_TYPES=9`, não subtrair nem equiparar.
Próxima implementação: produzir histogramas **apenas de classes genéricas e razões de ambiguidade**, sem IDs, nomes, SQL, paths ou dados; exercitar testes adversariais e pipeline sintético novamente antes de executar contra o backup real. Não gerar `CREATE ROLE`, nem mudar ambientes CLEAN6 ou produção.

## V6.6 experimental blind-spot classification (synthetic tests first)
- Independent module `scripts/GuardianV66-TocBlindSpotAudit.mjs` consumes TOC text **only in memory** and delegates basic count/duplication validation to V6.5.
- Separates formerly unrecognized items into (i) known, fixed *public pg_dump type labels* absent from V6.5's allowlist, and (ii) other unknown shapes. Its histogram contains only vetted PostgreSQL type labels (e.g. `STATISTICS DATA`, `EVENT TRIGGER`), **never** user names, object identifiers, SQL or user-supplied strings.
- Separates the V6.5 nonstandard last token into candidate-only-type and no-owner-proof-type counts; does not interpret either as a valid role.
- Regression fixtures assert that fabricated private identifiers and quoted owner names never occur in serialized output. Fail-closed on duplicate TOC ids or invalid size/count.
- CI: `guardian-v54-catalog.yml` now runs V6.6 synthetic tests on Linux and Windows. **New commit CI must be independently checked**; previous 34/34 belongs to older V6.5 commit and does not attest V6.6.
- V6.6 is **NOT wired into the authenticated Windows operator**. Existing authenticated V6.5 behavior is unchanged. Do not run the genuine backup or introduce a sixth script in the Windows command until the new code is tested and explicitly integrated behind the same safety controls.
- The 9 unknown types and 1 anomalous tail from the genuine archive remain unresolved, as the genuine TOC has not been provided to V6.6.

## V6.6 integrated diagnostic implementation — CI gate
Integrated V6.6 into the authenticated in-memory V5.4 catalog reader, with counters:
`BLIND_KNOWN_PUBLIC_KIND_ITEMS`, `BLIND_OTHER_UNKNOWN_SHAPES`,
`BLIND_NONSTANDARD_CANDIDATE_ITEMS`, `BLIND_NONSTANDARD_NO_PROOF_ITEMS`,
`BLIND_HISTORICAL_GLOBAL_ROLES_VERIFIED=NO`.
Crosschecks require known+other=V6.5 unknown and candidate+no-proof=V6.5 nonstandard; V5.5 accepts these only as an optional complete group with strict arithmetic validation. All names remain omitted.
V5.4 PowerShell operator now requires **six pinned files**: V53, V54, V64, V65, V66, and the operator PS1. Do not reuse five-file V6.5 download command with newly integrated V6.6 files. V6.4.2/V6.5 previous pinned scripts remain reproducible.
New synthetic PG17 integration assertions and corrupted safe-report tests added. **Real backup V6.6 not yet run; new commit-specific CI not yet approved.** No SQL, production modification, automated merge or installer rollout authorized.

## Authenticated real archive V6.6 operator evidence — 2026-11-25
User-provided sanitized local operator output on pinned six-file revision `3158d859b8283b91b40a5c5614cb8e966515054b`:
- Three ciphertext copies, matching expected SHA-256; full AES-GCM authentication and local PG17 `pg_restore --list` succeeded.
- Content fingerprint `EA995E37864FF769`, TOC items 919 (unchanged from V6.5), six extensions visible, 12 *owner-role candidate strings* (not verified globals).
- Baseline: `SHAPE_RECOGNIZED_TYPES=910`, `SHAPE_UNRECOGNIZED_TYPES=9`, `SHAPE_NONSTANDARD_LAST_TOKENS=1`, `SHAPE_HISTORICAL_GLOBAL_ROLES_VERIFIED=NO`.
- New V6.6 counters: `BLIND_KNOWN_PUBLIC_KIND_ITEMS=6`; `BLIND_OTHER_UNKNOWN_SHAPES=3`; `BLIND_NONSTANDARD_CANDIDATE_ITEMS=0`; `BLIND_NONSTANDARD_NO_PROOF_ITEMS=1`; `BLIND_HISTORICAL_GLOBAL_ROLES_VERIFIED=NO`.
- Reconciliations: 6 + 3 = 9 unrecognized; 0 + 1 = 1 anomalous tail; 910 + 9 = 919.
- Historic `TOC_TABLE=77`, `EXPECTED_USER_TABLES_REFERENCE=76` requires scope comparison, cannot attribute +1 to a rogue table.
- `PG_RESTORE_EXECUTED_SQL=NO`, `DATABASE_RESTORED=NO`, `ROLES_ACL_RESTORED=NO`, `PRODUCTION_TOUCHED=NO`, `RTO_4_TO_6_HOURS_PROVEN=NO`.
- Independent GitHub Actions on this same commit: **34/34 SUCCESS**, zero failures, including networkless synthetic PG17 encrypted archive catalog, Windows operator and preflight Windows/Linux.

**Risk gate:** 6 items are classifiable as known public PostgreSQL TOC kinds; they are NOT evidence that their contents or dependencies were validated. Three entries remain in unrecognized shapes; one anomalous tail is in a kind with no owner-proof semantics. A separate role/global/ACL inventory and isolated data restore remain mandatory. No plaintext, IDs, role names, object names or password have been committed here. Next diagnostic should expose only fixed public PostgreSQL kind labels and aggregated unknown-shape categories, in-memory, with negative privacy tests before reading the real archive.

## V6.7 experimental TABLE scope assessor (not connected to real archive operator)
- Added `GuardianV67-TableScopeAudit.mjs` and `test-GuardianV67-TableScopeAudit.mjs`, included in Linux/Windows synthetic CI. For authenticated TOC supplied by trusted caller, aggregate only fixed structural classes of `TABLE` entries: public, another syntactically simple schema, no schema and complex/ambiguous schema.
- Redacted output NEVER returns table/schema/owner names; never equates `TOC_TABLE` with the live count of user tables, and never infers roles. Test includes private identifiers, quoted schema, duplicate entry IDs and no-SQL guardrails.
- Experimental only: **not imported by authenticated reader, not in Windows operator bundle and not executed on the real archive**. No extra operator command warranted until explicit integration, new CI success and authentic report safety validation.

## V6.7 authenticated TOC scope integration (new CI required)
- V6.7 TABLE scope assessor imported into authenticated catalog, counts reconciled with `TOC_TABLE` and `TOC_TABLE_DATA`. Diagnostic reports four **only aggregated** fields: `SCOPE_PUBLIC_SCHEMA_TABLES`, `SCOPE_OTHER_SIMPLE_SCHEMA_TABLES`, `SCOPE_NO_SCHEMA_TABLES`, `SCOPE_COMPLEX_SCHEMA_TABLES`, plus the explicit safeguard `SCOPE_ORIGINAL_USER_TABLES_VALIDATED=NO`.
- V5.5 preflight accepts these fields optionally for backward compatibility, rejects partial groups and any sum different from `TOC_TABLE`. Integration and negative tests updated.
- PowerShell operator now requires **seven** local scripts, including V67, before prompting for backup credentials. Older six-file V6.6 pinned bundle is only valid for its original pinned commit; never mix source versions.
- This version has not yet been tested against the real encrypted archive. Run no genuine backup until **new commit-specific full synthetic integration + Windows operator + preflight CI** completes.

## V6.7 authenticated real backup evidence
User-provided safe operator result on seven-file V6.7 integration (full 34/34 green CI on commit `23f6f6e03ee37fa0d715ec871a32a66a91576128`):
- Ciphertext copies 3/3 matching, AES-GCM valid, PG17 networkless `pg_restore --list` pass; `ARCHIVE_CONTENT_SHA16=EA995E37864FF769`, `ARCHIVE_CATALOG_ITEMS=919`.
- `SCOPE_PUBLIC_SCHEMA_TABLES=25`, `SCOPE_OTHER_SIMPLE_SCHEMA_TABLES=52`, `SCOPE_NO_SCHEMA_TABLES=0`, `SCOPE_COMPLEX_SCHEMA_TABLES=0`; arithmetic 25+52=77 `TOC_TABLE`.
- `TOC_TABLE_DATA=73`; the numerical difference 77-73=4 is not proof of missing table data, missing rows, or restore failure. No table/data pairing proof yet.
- Original user table reference remains 76, but archival TOC includes tables in multiple schemas. `SCOPE_ORIGINAL_USER_TABLES_VALIDATED=NO` and no mapping to historical user-table scope.
- V6.6 unchanged: six known PostgreSQL descriptor-kind entries not recognized by V6.5 and three other unknown; one nonstandard tail in a no-owner-proof type. Historical global roles/ACL not validated.
- `PG_RESTORE_EXECUTED_SQL=NO`, `DATABASE_RESTORED=NO`, `ROLES_ACL_RESTORED=NO`, `PRODUCTION_TOUCHED=NO`.
No credentials, schema/table/object names or backup data stored.

## V6.8 experimental TABLE / TABLE DATA pairing audit
`GuardianV68-TableDataPairAudit.mjs` now provides an **in-memory, diagnostic-only** pairing of entries whose schema, object and owner tokens are trivially ASCII-safe. It returns only bounded counters: uniquely paired entries, simple unpaired table entries, simple unpaired data entries, structurally ambiguous entries and duplicated/nonunique entries. It does **not** output, persist or hash identifiers (including names of tables or schemas). It does not inspect actual rows, deduce empty or missing tables, verify historical scope, or certify recoverability. Quoted/spaced names are treated as ambiguous; no false exact matches are asserted.

Tests on invented private schemas/tables ensure counter reconciliation and no name output; Linux and Windows isolated CI configured. The experimental V6.8 module is **not wired** to the authenticated catalog or Windows operator yet. Existing seven-file V6.7 operator remains unchanged. **New commit CI not yet verified**; no real-backup execution authorized by this new module.

## V6.8 integrated authenticated catalog (commit-specific CI required)
V6.8 is now wired into authenticated `GuardianV54-ArchiveCatalog.mjs`, the defensive V5.5 report parser and the local operator. The operator now requires **eight** locally SHA-pinned files: V53/V54/V64/V65/V66/V67/V68 and PS1. New `PAIR_` counters are unique structural pairs, unmatched simple entries (table and data separately), ambiguous entries (table and data separately) and duplicate/nonunique entries; `PAIR_ROWS_VERIFIED=NO` is mandatory. The report parser sums independently against `TOC_TABLE` and `TOC_TABLE_DATA`, rejects inconsistent, incomplete, or overly optimistic fields, but allows previous versions' reports. Synthetic authenticated integration and tamper tests extended.
No table names, schema names, historical role names, SQL or actual rows are in the report. This structural-only audit does not prove missing or present rows and cannot settle user-table reference 76 on its own. **Do not run this eight-file operator on real backup until GitHub Actions for the integration commit has succeeded**, and do not reuse the seven-file V6.7 bundle with this code.

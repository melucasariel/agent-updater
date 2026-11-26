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
- **Não há integração do auditor novo com o operador local neste commit.** O operador autenticado V6.4.2 permanece intocado. A inclusão em CI não significa aprovação até que runs no SHA final sejam verificadas.
- **Atenção às métricas:** `typesWithoutOwnerProof` conta entradas cujo *tipo* não autoriza inferir proprietário, e não prova que essas entradas não tenham proprietário no PostgreSQL. `structuralOwnerCandidatesOnly` também não representa roles reais.

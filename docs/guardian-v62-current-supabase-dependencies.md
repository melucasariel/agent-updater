# ROTA62 Guardian V6.2 — evidência real de dependências PostgreSQL atuais (não é snapshot histórico)

Data: 2026-11-25, arquivo disponibilizado pelo operador em resposta à query de metadados read-only do Supabase.

## Fatos comprovados pelo relatório ATUAL

- `postgres_version`: **17.12**.
- **31 roles** presentes, incluindo roles gerenciadas Supabase e funções internas PostgreSQL.
- **7 extensões instaladas** (nome, versão, schema): `pg_cron` 1.6.4/pg_catalog; `pg_net` 0.20.4/public; `pg_stat_statements` 1.11/extensions; `pgcrypto` 1.3/extensions; `plpgsql` 1.0/pg_catalog; `supabase_vault` 0.3.2/vault; `uuid-ossp` 1.1/extensions.
- **5 identidades proprietárias de objetos** na consulta: `postgres`, `supabase_admin`, `supabase_auth_admin`, `supabase_realtime_admin`, `supabase_storage_admin`.
- **27 entradas** em `pg_default_acl`, no banco atual.
- **5 roles com BYPASSRLS** (`postgres`, `service_role`, `supabase_admin`, `supabase_etl_admin`, `supabase_read_only_user`) e **uma role SUPERUSER**, `supabase_admin`.

## O que o resultado NÃO prova

- Os sete nomes de extensão atuais NÃO são automaticamente equivalentes às seis entradas `EXTENSION` do TOC do `.r62db` verdadeiro. A diferença pode ser de escopo e do tratamento de extensões preexistentes; só um comparador de identidades de catálogo de origem pode concluir.
- Os 31 roles atuais NÃO são um backup globals oficial de sua versão do dia da captura. As roles `pg_*` podem ser predefinidas pelo PostgreSQL e as `supabase_*`, `anon`, `authenticated`, `service_role` são gerenciadas pelo stack. Recriá-las manualmente no destino sem revisar as permissões seria inseguro.
- `27 DEFAULT ACL` no catálogo atual e 27 entradas `TOC_DEFAULT_ACL` no backup não provam igualdade de owners, grantees nem privilégios.
- O relatório não inclui memberships de roles, atributos completos de `pg_authid`, passwords, grants de schema, configurações, objetos Storage, backups web/API ou prova do mesmo ponto de captura.
- Postgres 17.12 do ambiente atual NÃO garante que todas as extensões e dependências do ambiente de recuperação estejam disponíveis na mesma versão.

## Novo código V6.2

`scripts/GuardianV62-CurrentDependencyEvidence.mjs` aceita JSON **de metadados atuais** e valida estritamente a forma do relatório, contagens de roles, privilégios sensíveis, extensões de rede/cron e owners, com saída sanitizada. Ele falha fechado se aparecerem campos desconhecidos como tokens, passwords ou credenciais, listas duplicadas e owners fora da lista de roles. **Nenhuma SQL é executada.**

O módulo nunca apresenta o relatório como histórico original; retorna `ORIGINAL_BACKUP_ROLES_ATTESTED=NO`, `ORIGINAL_BACKUP_EXTENSIONS_ATTESTED=NO` e `READY_TO_RESTORE_REAL_BACKUP=NO`.

Os testes sintéticos de Windows e Linux estão em `.github/workflows/guardian-v62-dependency-evidence.yml`, sem usar o relatório real em repositório público.

## Próximo passo técnico

Obter evidência read-only do **ambiente atual** das relações de membros/grants e das extensões, sem senhas, apenas para pré-verificação. Em paralelo, validar se existe um globals oficial/roles snapshot com proveniência ligada ao `.r62db` autêntico. Só então provisionar um destino PostgreSQL 17 descartável e sem rede e testar restore real sem flags `--no-owner`/`--no-privileges`.

**Importante**: nenhuma instrução autoriza a executar `CREATE ROLE` ou elevar permissões no Supabase atual. O sistema de produção e os quatro containers CLEAN6 anteriores continuam intocados.
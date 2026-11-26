# Guardian V6.3 — Dependências reais atuais: roles, owners, DEFAULT ACL

## Evidência fornecida pelo operador (somente leitura, ambiente atual)

A consulta SQL `guardian_roles_dependency_report` foi executada no Supabase atual e enviada como arquivo de texto. Nenhuma senha, token, dado de corrida ou SQL de mutação foi solicitado. O diagnóstico informa `evidence=CURRENT_METADATA_ONLY`, portanto NÃO equivale a backup histórico de roles do `.r62db` real.

Contagem verificada no arquivo recebido:

- `role_memberships`: **24** vínculos distintos, com `ADMIN OPTION` habilitado em **8**, `INHERIT OPTION` em **17**, `SET OPTION` em **24**.
- `object_owners`: **9 grupos** schema/proprietário, totalizando **306 objetos `pg_class`**: `auth` 140, `cron` 7, `extensions` 2, `net` 6, `public` 79, `realtime` 31 (em dois owners), `storage` 37, `vault` 4. Existem **cinco roles distintas proprietárias** neste relatório: `postgres`, `supabase_admin`, `supabase_auth_admin`, `supabase_realtime_admin`, `supabase_storage_admin`.
- `default_acls`: **27** entradas agrupadas, em `public` 6, `storage` 3, `cron` 3, `extensions` 3, `graphql` 3, `graphql_public` 3, `realtime` 3, `auth` 3. Tipos `S` sequências, `f` funções e `r` relações.
- Os schemas identificados nos objetos são **oito**: `auth`, `cron`, `extensions`, `net`, `public`, `realtime`, `storage`, `vault`. Os schemas cobertos pelas DEFAULT ACLs também são oito, mas não são necessariamente os mesmos.

### Duas diferenças de escopo que NÃO demonstram perda de dados

- O inventário autentificado do backup histórico apresentou 77 entradas `TABLE`; 79 objetos `pg_class` atuais no `public` englobam índices, tabelas, sequências e outros tipos de relação — não comparar essas duas contagens.
- 27 DEFAULT ACL atuais e 27 entradas no TOC histórico **não** provam identidade de `grantor`, `grantee`, owner, objetos ou privilégios. Devem ser comparadas por atributos/identidade semântica, após restaurar o backup real.

## Implementação V6.3

`scripts/GuardianV63-CurrentRoleGraph.mjs` recebe exclusivamente um JSON local proveniente da consulta read-only, valida semântica e campos, recusa duplicidades, detecta ciclos no grafo de membership, soma os objetos/ACLs e produz somente relatório de contagens e digest abreviado. Não executa SQL, não cria grants, não tenta restaurar roles e não expõe os nomes presentes no JSON de entrada. O SQL de um futuro `pg_dumpall --globals-only` deve continuar separado e exigir proveniência.

`.github/workflows/guardian-v63-role-graph.yml` executa testes com dados inteiramente sintéticos em Windows e Linux, incluindo grants duplicados, schemas/owners duplicados, campos inesperados e ciclos.

## Condição para destravar o primeiro restore de dados REAIS

1. Obter arquivo de globals das roles COM PROVENIÊNCIA VINCULADA à versão histórica ou validar perfil de roles gerenciadas do ambiente descartável por documentação oficial e equivalência testada.
2. Ter PostgreSQL 17 com extensões verificadas e rede bloqueada de verdade; bloquear triggers, cron e pg_net de efeitos externos.
3. Restaurar o `.r62db` verdadeiro já autenticado em destino NOVO e descartável. Não executar `CREATE ROLE`/`GRANT` no Supabase atual nem nos quatro containers CLEAN6.
4. Comparar owners, grants, DEFAULT ACL, RLS, constraints e funções; reconciliar 77 TABLE TOC vs escopo 76 anterior sem apagar objetos.
5. Recuperar Site/API/Storage/Secrets independentemente e cronometrar RTO 4–6h antes de afirmar recuperação pronta.

Política permanece: backups MANUAIS antes de atualização. Não adicionar backup agendado automático de quatro em quatro horas.
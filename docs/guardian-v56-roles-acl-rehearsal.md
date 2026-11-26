# ROTA62 Guardian V5.6 — prova de restauração fiel de proprietários e permissões

## Conclusão do V5.4 com o arquivo verdadeiro

O operador confirmou um `.r62db` real SHA-256 `35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA`, com autenticação AES-GCM e inventário de **919** objetos PostgreSQL obtido por `pg_restore --list` sem executar SQL. O inventário contém 77 entradas `TABLE`, 73 de `TABLE DATA`, 210 `ACL`, 27 `DEFAULT ACL`, 6 extensões, 8 políticas RLS e 52 `ROW SECURITY`. Uma auditoria de escopo anterior reportou 76 tabelas. **A diferença não é prova de perda**; depende da interpretação do objeto de catálogo e do escopo da consulta.

## V5.5 — pré-voo declarativo

`scripts/GuardianV55-RecoveryPreflight.mjs` valida de forma rigorosa um relatório de catálogo sanitizado, confere a soma de todas as categorias, impede duplicatas e bloqueia dependências sem evidência. O parser **não autentica criptograficamente o arquivo de relatório**: ele apenas confere conteúdo e formato. Qualquer relatório pode ser forjado, portanto ele não serve como prova independente de origem.

## V5.6 — ensaio funcional sintético de roles e ACL

`.github/workflows/guardian-v56-owner-acl-restore.yml` utiliza dois containers PostgreSQL 17 **exclusivos e isolados**, sem portas publicadas, com dados sintéticos. O primeiro exporta `pg_dump -Fc` e `pg_dumpall --globals-only` de um banco com role proprietária, role leitora, schema, tabela, índice, dados artificiais, GRANT, DEFAULT ACL e política RLS. O segundo **primeiro tenta restaurar sem as roles e deve falhar sem tabelas parcialmente criadas**; depois recebe somente definições de roles aprovadas nesse fixture sintético, restaura com `pg_restore --single-transaction --exit-on-error` e **sem** `--no-owner` nem `--no-privileges`, comparando via catálogo proprietário, GRANT, DEFAULT ACL, RLS, índices e dados.

**Importante:** não aplicar um `pg_dumpall --globals-only` vindo de origem desconhecida automaticamente em produção. A etapa de laboratório cria roles explicitamente conhecidas, pois a transposição de roles Supabase requer controle de perfis gerenciados, permissões e compatibilidade. Os dumps e o SQL gerados nos testes são sintéticos e são descartados.

## Critério de aceite futuro para recuperação real

1. Destino PostgreSQL 17 novo, isolado, sem acesso a redes de produção, serviços de terceiros, pg_net, cron ou secrets reais.
2. Roles globais oficiais e dependências da origem **autenticadas e revisadas antes do restore**; não derivar roles apenas de nomes no TOC.
3. Restauração do ciphertext original autenticado em streaming sem deixar arquivos plaintext em disco, com owners/ACL/DEFAULT ACL preservados ou equivalência **demonstrada**.
4. Comparador de catálogos com escopo explicitamente documentado e análise específica 77 vs 76, sem apagar objetos para fazer bater contagens.
5. Reinstalar API, frontend, Storage e configurações; secrets somente por cofre local e sem publicação acidental.
6. Teste de corridas sintéticas/HTTP e RTO de 4–6 horas medido, com confirmação humana antes de DNS/cutover.

Por enquanto, a restauração verdadeira do TaxiRadar ainda **não aconteceu**. A produção e os quatro containers CLEAN6 do operador continuam fora do alcance desses testes.
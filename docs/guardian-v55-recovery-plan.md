# ROTA62 Guardian V5.5 — Plano de recuperação que falha fechado

## Resultado real do operador em 25/11/2026

O V5.4.1 executado no Windows do operador conseguiu confirmar **AES_GCM_TAG_AUTHENTICATED=YES**, **PG_RESTORE_CATALOG=PASS**, imagem PostgreSQL 17 local verificada, fingerprint abreviado do conteúdo `EA995E37864FF769` e catálogo com 919 itens. Nenhum SQL foi executado, nenhum banco foi restaurado, nenhum dado em claro foi salvo e a produção permaneceu intocada.

Resumo **anonimizado** do catálogo: TABLE 77, TABLE DATA 73, ACL 210, DEFAULT ACL 27, EXTENSION 6, FUNCTION 87, INDEX 128, POLICY 8, ROW SECURITY 52, TRIGGER 15, OTHER 13. A contagem anterior do auditor CLEAN6 é de 76 tabelas no escopo específico de pg_class usado naquela auditoria. Isso é uma diferença de escopo a investigar, não prova de tabela perdida.

## Implementado

`scripts/GuardianV55-RecoveryPreflight.mjs` aceita **somente relatórios sanitizados com os campos esperados do V5.4**, mas não verifica sua autenticidade criptográfica. Valida campos, permissões e estados esperados, fingerprint abreviado, soma completa das categorias TOC e proíbe duplicatas, campos desconhecidos e status implausível de produção/restauração. A saída diferencia `CATALOG_REPORT_FIELDS_VALIDATED=YES` de `REPORT_CRYPTOGRAPHIC_AUTHENTICITY=NOT_ATTESTED` e lista dependências **BLOQUEADAS até evidência verificável**, que não faz SQL, não acessa Docker, não lê o `.r62db` nem recebe senha.

Exemplos de dependências bloqueantes: restauração oficial de roles globais, owners, ACLs e DEFAULT ACL; compatibilidade das seis extensões; isolamento de triggers, funções, cron e callbacks externos; conferência de políticas RLS; distinção entre o escopo TABLE 77 vs. pg_class 76; revisão das 13 entradas TOC de tipo ainda não classificado; Storage, Web, API, configurações, cofre de secrets e chave de recuperação externa; ensaio completo com RTO de 4–6 horas.

### Princípio de segurança

- O TOC de `pg_restore --list` **não contém os objetos globais** que podem ser necessários para recriar roles. Exigir fonte de roles oficial (`pg_dumpall --globals-only` ou equivalente do ambiente Supabase) e validar sua origem antes de tentar `pg_restore` com ACL.
- Uma entrada `TABLE DATA` não revela número de linhas nem garante que cada `TABLE` tenha um item de dados; podem existir tabelas sem payload, partições e objetos com escopo diferente.
- O número 210 de ACLs é uma contagem de *entradas do arquivo*, distinta das 1.541 tuplas de permissões da exportação pg_catalog. Comparação exige normalização por identidade e escopo.
- `ROW SECURITY=52` não equivale a 52 políticas; as políticas são oito itens de outra categoria e não devem ser comparadas diretamente.
- O Guardian nunca deverá usar silenciosamente `--no-owner` ou `--no-privileges` para mascarar falhas de roles.
- O manifesto pronto e o plano de pré-voo não garantem recuperação do TaxiRadar, versão exata nem que API, Web e Storage estão completos. Não se deve liberar produção ou afirmar RTO validado.

## Exemplo de execução a partir do relatório sanitizado

Escreva as linhas do relatório V5.4 em um arquivo privado **sem incluir senha ou nomes de objetos**, como `C:\R62_PRIVATE\catalog-safe.txt`, e execute em checkout verificado:

```powershell
node .\scripts\GuardianV55-RecoveryPreflight.mjs --safe-report C:\R62_PRIVATE\catalog-safe.txt
```

O programa não gera backup, nem altera o conteúdo do arquivo. A integração do pré-voo será usada pelo restaurador V5.6 para bloquear etapas que não tenham evidência.

## Aceite de recuperação real (ainda NÃO atendido)

1. Integrar os exporters de roles globais e source packages da mesma versão do backup original.
2. Construir restore de PostgreSQL novo com rede isolada real e sem conectividade externa, correndo `pg_restore --exit-on-error --single-transaction` e reaplicando ACL/DEFAULT ACL determinísticamente.
3. Reconstruir catálogo do banco restaurado e comparar owners e grants com a fonte **original autenticada**, não apenas as quatro instâncias provisórias já modificadas.
4. Validar referências de dados e triggers/functions/cron/pg_net sem chamadas reais de push/pagamento.
5. Restaurar Storage, Edge/API, frontend Cloudflare, DNS e secrets recuperados localmente via cofre isolado.
6. Ensaiar o fluxo de corridas sintético, login e HTTPS em ambiente novo, medir RTO real e confirmar a passagem para produção separadamente.
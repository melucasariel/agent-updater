# ROTA62 Guardian — Registro permanente de erros, correções e regras de não regressão

**Versão:** 2026-11-25 / Guardian V5.2. Este arquivo é a referência técnica para os próximos releases. Não trate testes sintéticos como recuperação real. Não coloque dados privados no repositório público.

## Decisões definitivas do operador

- Backups **manuais**, principalmente imediatamente antes de cada publicação do TaxiRadar; nenhum cron de backup a cada quatro horas.
- Objetivo de RTO **4–6 horas**, mensurado exclusivamente por ensaio real do pacote completo; não prometer restauro instantâneo.
- Uso simples: três ações **Criar Backup**, **Testar Recuperação**, **Recuperar Sistema**; cada operação tem gate, relatório e bloqueio quando faltam provas.
- PowerShell: um bloco colar+Enter, resultados sanitizados copiados automaticamente para clipboard; jamais incluir tokens, chaves ou senha em stdout.
- Alterações e testes em lote (major releases), não ciclo interminável de pequenos diagnósticos. Não solicitar confirmação para avançar em etapas locais sem efeitos irreversíveis.

## Falhas históricas transformadas em regras de engenharia

| Erro observado nas versões anteriores | Regra que não pode regredir | Validação atual |
|---|---|---|
| Dump PostgreSQL restaurado com roles, owners, ACL e DEFAULT ACL incompletos | Nunca omitir GRANT/owner; restaurar roles/ACL de forma determinística antes de declarar sucesso | V5.1 falha corretamente se GRANT cita role ausente; equivalência integral com fonte continua pendente |
| Contar 55 vs. 56 ACL ou misturar escopos 185/595 vs. 368/1541 | Comparar objetos por identidade, ACL tuple por chave completa; documentar escopo e nunca comparar contagens diferentes como se fossem mesma métrica | CLEAN6 four-way e exportador PG17 |
| Confundir três arquivos iguais com três snapshots históricos | SHA-256 iguais significam um único ponto de recuperação; deduplicar e reportar isso | V5.2 `DISTINCT_RECOVERY_POINTS` |
| Hash de ciphertext tratado como prova completa | Separar SHA-256, autenticação AES-GCM, proveniência, consistência lógica e teste funcional | V5.2 emite `CRYPTOGRAPHIC_AUTHENTICATION_PERFORMED=NO` |
| Relação entre backup `.r62db` e containers PG17 assumida sem prova | Não atribuir restauração a arquivo só porque tabela/ACL têm mesmas contagens | V5.2 vincula o stage ao SHA mas ainda não declara recuperação |
| PostgreSQL reporta pg_isready antes do servidor definitivo | Exigir conexões SQL repetidas ao banco-alvo; confirmar 17 antes de restore | V5.1 integra teste de fixture PG17 e cleanup |
| SQL inválido no PowerShell, parse do tipo generics, erros de stdout Docker tratados como fatal, EPIPE e `undefined.message` | Separar `.ps1`/`.sql`/`.mjs`; CI Linux e Windows; tratar falhas sanitarizadas, não imprimir stderr privado | CI multiplataforma V4/V5/V5.1/V5.2 |
| Cron, pg_net, push e callbacks externos podem disparar no restore | Laboratório nunca deve ter rede de saída nem secrets de produção; testar apenas mocks | V5.1 Docker internal; prova de isolamento absoluto e E2E ainda pendente |
| Confundir ZIP de 52 arquivos com backup do app todo | Exigir Web, API, Database, Storage, DNS, Config, vault separado; fail closed | V4 sete componentes, V5 seis preparados + cofre externo |
| Falta de restores novos de Web/API/Storage e autenticação | Não marcar `RECOVERABLE` sem HTTP, login fictício, fluxo de corrida sintética e validações | Ainda pendente |
| Produção alterada por teste de laboratório ou ambiente Docker com host port publicado | Somente destinos descartáveis, redes internas e publicação após autorização humana | V5.1 sem portas e sem contexto remoto |
| Keys/secrets encontrados em HD externo mas não restaurados | Nenhum secrets em GitHub/clipboard; vault separado com procedimento testado | Ainda pendente |
| Efeito de deploy/cutover e DNS assumido | Plano e ensaio separados; nunca alterar DNS automaticamente em teste | Scripts atuais não publicam |
| Reuso do próprio backup para inventar referência independente | Referência imutável fora do backup e histórico de custódia; detectar fraude de origem | Ainda pendente |

## Evidências do operador (não públicas, apenas agregados de diagnóstico)

- Três arquivos `.r62db` idênticos de 5.287.976 bytes, criptografia R62DB02/AES-GCM+scrypt, `SHA-256=35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA`.
- Quatro restaurações PG17 com 76 tabelas e seis extensões além de plpgsql. Duas equivalentes no escopo de catálogo (368 owners, 1541 ACL), outras duas com 10/17 registros adicionais. Não há prova de qual deriva do ciphertext.
- A recuperação original v0.5 demonstrou leitura/restauração parcial real, porém não constitui prova integral de deploy e disaster recovery. Código decriptador comprovado deve ser reaproveitado, não reescrito a partir de suposições do envelope R62DB02.

## Critérios de saída por release

1. **V5.2**: confirmar integridade do ciphertext e cópias, verificar stage independente e rejeitar SHA adulterado. Não tocar na produção nem pedir senha.
2. **V5.3**: integrar decriptador real previamente auditado ao PostgreSQL 17 isolado, com zero arquivos plaintext persistentes, senha local sem eco, confirmação de autenticação AES-GCM e prova independente de roles/ACLs.
3. **V5.4**: API, Web, Storage, config/secret-vault em novo destino; testes funcionais sintéticos, bloqueio comprovado de egress e smoke test HTTPS.
4. **V6**: aplicação pronta somente após ensaio integral com RTO 4–6 horas medido, pacote completo com cópia offsite, logs protegidos e confirmação explícita antes de publicação.

### Classificações que NÃO podem ser usadas indevidamente

- `HASH_VERIFIED` ≠ `AES_GCM_AUTHENTICATED` ≠ `RESTORED_IN_LAB` ≠ `FUNCTIONAL_APPROVED` ≠ `PRODUCTION_RECOVERED`.
- A aprovação do GitHub Actions em Docker sintético prova apenas o código/teste CI. Não prova que o computador do usuário tem o mesmo código ou que seu arquivo real foi aberto.
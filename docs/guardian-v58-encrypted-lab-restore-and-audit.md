# Radar Guardian V5.8 — revisão de arquitetura, autêntico pipeline criptografado em laboratório

## Escopo real deste release

O objetivo operacional do operador é backup **manual** antes das atualizações, recuperação do TaxiRadar (PostgreSQL, Web, API, Storage, configuração e cofre de secrets independente) em **4 a 6 horas**. Esse RTO **não foi ainda comprovado**. Nunca ligar backup agendado de quatro em quatro horas sem ordem explícita. Não alterar produção ou os quatro containers CLEAN6 existentes.

### Evidências do backup verdadeiro já obtidas pelo operador

- Três cópias com SHA256 idêntico `35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA`, 5.287.976 bytes: **um ponto histórico**, não três.
- AES-256-GCM e scrypt do envelope original `R62DB02` autenticados, plaintext `PGDMP` 5.287.733 bytes, fingerprint abreviado `EA995E37864FF769`; arquivo descriptografado não gravado em disco.
- TOC original 919 entradas: `TABLE=77`, `TABLE DATA=73`, `ACL=210`, `DEFAULT ACL=27`, `EXTENSION=6`, `FUNCTION=87`, `INDEX=128`, `POLICY=8`, `ROW SECURITY=52`, `TRIGGER=15`, `OTHER=13`. `TABLE=77` versus 76 de auditoria anterior exige revisão de escopo, não eliminação de tabela. Os metadados não são a restauração.

## O que V5.8 implementa e demonstra

- `scripts/GuardianV58-EncryptedLabRestore.mjs`: caminho integral **SOMENTE DE DADOS SINTÉTICOS**: valida destino PostgreSQL 17 via contexto Docker local, nome, label exclusiva, rede interna, zero portas publicadas e ausência de bind mounts; confere SHA do ciphertext; autentica o R62DB02 AES-GCM inteiro **antes** de iniciar `pg_restore`; confere que o ciphertext não mudou; transmite plaintext para `pg_restore --single-transaction --exit-on-error` via stream, sem gravar novo arquivo desencriptado; compara digest de plaintext e confere novamente ciphertext após a restauração. Nunca aceita senha real por parâmetro, nem possui modo `--real-backup`.
- `scripts/test-GuardianV58-MakeSyntheticArchive.mjs`: converte dump PostgreSQL sintético da CI num `R62DB02` com o mesmo envelope AES-GCM/scrypt do script original; senha CI falsa fornecida somente em variável do runner sintético.
- `.github/workflows/guardian-v56-owner-acl-restore.yml`: expande o ensaio PostgreSQL17 anterior para restaurar o fixture **a partir do ciphertext**, exige que senha errada, SHA incorreto e tag adulterada bloqueiem **antes de criar tabelas parciais**; com roles pré-provisionadas, deve restaurar owners, grants, DEFAULT ACL, policies, índices e dados; compara catálogos e detecta REVOKE intencional.
- `.github/workflows/guardian-v58-safety-smoke.yml`: teste Windows + Linux das interfaces de execução que bloqueiam uso de backup verdadeiro e exigem credencial sintética.
- `scripts/GuardianV57-CanonicalCatalog.sql`: corrigida classificação semântica independente dos OIDs internos de roles: ACLs passam a ser ordenadas por nomes de grantee/grantor. O search_path do catálogo fica fixo em `pg_catalog` para evitar renders diferentes conforme o ambiente. A CI cria a mesma role em ordens diferentes nas duas bases.

## Erros anteriores tratados como gates permanentes

1. **`pg_restore --no-owner --no-privileges`**: esse caminho era a origem de restaurações com ACL incompleta. V5.8 exige roll-forward com `--single-transaction --exit-on-error` sem essas opções. Um dump com role ausente falha e não cria tabelas parciais.
2. **Senha ou GCM falsos**: nunca executar SQL antes da primeira autenticação AES-GCM completa e da verificação SHA. Em segunda passagem, verificar hash do plaintext e tag outra vez. Não registrar secrets, SQL ou nomes privados no console.
3. **Restaurar no container errado**: bloquear destino sem label explícita e nome aleatório conhecido, com mount host ou porta publicada, redes não internas, Docker remoto e PostgreSQL major diferente de 17.
4. **IDs de roles não estáveis**: comparar ACLs por nomes das roles, e não OIDs numéricos, além de injetar diferenças controladas de permissão.
5. **Confundir contagens iguais com conteúdo igual**: comparação canônica por SHA-256 normalizado, com teste de REVOKE alterando assinatura apesar de tabelas iguais.
6. **Tratar o ZIP só do banco como recuperação integral**: o sistema só será considerado pronto depois de recuperar Web, API, Storage, cofre de secrets e destinos Cloudflare/Supabase funcionais e ensaio cronometrado.

## Restrições de uso do restaurador V5.8

**NÃO utilizar com o `.r62db` verdadeiro.** Este código exige container com label de fixture sintético e exige `--mode synthetic-ci`; foi projetado para comprovar o caminho e suas falhas sem qualquer ligação com produção. Antes do restore autêntico, faltam globals/roles oficiais, permissões DEFAULT ACL, extensões compatíveis e fonte confiável para comparar contra o catálogo original; em execução de SQL sob superuser, extensões/funções podem ter efeitos não-transactionais, por isso é imprescindível um destino descartável sem egress e sem chaves reais.

Não é possível afirmar 'restauração real concluída' apenas por sucesso do CI. Ainda não foram executadas SQL de restauração sobre o conteúdo real do TaxiRadar.

## Próximo gate para habilitar o modo real

Recuperar pacote oficial de roles globais e referências dos schemas do MESMO backup autenticado, com integridade e proveniência independentes; executar no isolamento descartável um restore de teste com controle de extensões/funções/pg_net/cron, sem secrets e sem acesso externo; comparar catálogos e conferência de dados; somente então liberar opção operacional de recuperação e o fluxo de Web/API/Storage.

Referência técnica para flags PostgreSQL 17: https://www.postgresql.org/docs/17/app-pgrestore.html
# ROTA62 Guardian V6.4 — Dependências do arquivo criptografado autenticado

## Problema concreto resolvido

O `.r62db` verdadeiro já foi autenticado em Windows e o `pg_restore --list` exibiu **919 itens**, mas V5.4 só fornecia contagens de classes, não um inventário seguro das **roles proprietárias visíveis** nem das **extensões listadas**. Para planejar restore exato sem usar `--no-owner`/`--no-privileges`, esse resumo é útil, porém não é um dump das roles globais.

`scripts/GuardianV64-TocDependencyPreflight.mjs` extrai sem persistir nomes o conjunto de candidatos a owner e nomes das entradas EXTENSION de um TOC. Pode ser usado como módulo em memória no processo V5.4 depois de autenticar integralmente AES-GCM e descriptografar o arquivo na execução `pg_restore --list` networkless. Nada imprime nomes, funções, SQL, registros ou caminhos privados.

## Integração real de módulos

O script autenticado `GuardianV54-ArchiveCatalog.mjs` agora calcula adicionalmente `DEPENDENCY_VISIBLE_OWNER_ROLES`, `DEPENDENCY_DISTINCT_EXTENSIONS`, `DEPENDENCY_UNCLASSIFIED_TOC_ENTRIES`, `DEPENDENCY_AMBIGUOUS_TOC_OWNER_ENTRIES`, `DEPENDENCY_SHA16` e marca `DEPENDENCY_ROLE_GRANTEES_COMPLETE=NO`. A saída continua informando que NENHUM SQL foi executado.

O `GuardianV55-RecoveryPreflight.mjs` valida esses campos **opcionais** de V6.4 fora da soma de `TOC_...`, e continua aceitando o relatório V5.4 antigo sem alterações. Não afirma que o novo arquivo de relatório é assinado — somente o ciphertext é autenticado no V5.4.

O operador `Invoke-GuardianV54-Catalog.ps1` verifica que o novo parser V6.4 existe e passa em `node --check` antes de pedir a senha; a versão antiga do comando é fixada em commit anterior e permanece reproduzível. Uma nova distribuição Windows deve baixar V53, V54, V64 e PS1 em **mesmo commit revisado**, conferindo os Git blob SHA-1 dos quatro arquivos.

## Comparação com o Supabase ATUAL

O parser V6.4 permite comparar em memória o conjunto de owners/extensões com um JSON local do V6.2 (`evidence=CURRENT_METADATA_NOT_ORIGINAL_BACKUP_PROOF`). Quando houver identidades ausentes, informa APENAS contagens. O CLI offline de TOC pode ler esses arquivos privadamente mas exige que o TOC tenha sido obtido de fonte confiável: o CLI sozinho não autentica o `.r62db` e não deve ser interpretado como prova histórica.

**Vedações:** não gerar comandos `CREATE ROLE`, não recriar roles gerenciadas Supabase só porque estão no relatório atual, não assumir que o TOC contém grantees, memberships ou atributos globais completos. Uma role identificada no final do texto do TOC pode não ser parseável em formatos incomuns; o parser é conservador e preserva contador de itens ambíguos/desconhecidos. A contagem de EXTENSION do TOC e o total de extensões instaladas no banco atual têm escopos diferentes.

## Evidências e CI

Testes novos do V6.4 exercitam linhas sintéticas do `pg_restore --list`, identificam extensões/owners diferentes, erro por ID de item duplicado e metadados não históricos falsamente marcados. Os testes V5.4 criptografados e V5.5 de compatibilidade foram ampliados. Todos usam fixtures, sem backup verdadeiro ou senha real.

## Dependências para restauração real

1. Identificar o conjunto de roles globais da época do snapshot por fonte autenticada independente e comparar memberships, owner e grants; os relatórios atuais V6.2/V6.3 são apenas referência atual.
2. Preparar destino PostgreSQL17 compatível com Supabase e extensões, isolado de rede externa, cron e pg_net; NUNCA reusar os quatro containers CLEAN6.
3. Restaurar somente no destino novo, dentro de testes sem efeitos externos e com proprietários/ACLs intactos, comparar dados reais e catálogos completos.
4. Recuperar Web, API, Storage, DNS/config/secrets e cronometrar recuperação completa antes de declarar 4–6 horas comprovadas.

Backups MANUAIS imediatamente antes das atualizações, sem rotina automática a cada quatro horas.
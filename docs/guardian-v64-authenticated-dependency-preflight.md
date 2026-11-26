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
## Correção de evidência real após execução local — V6.4.1

Em nova execução do operador com o `.r62db` autêntico, o Guardian voltou a autenticar `AES_GCM_TAG_AUTHENTICATED=YES` e a listar 919 itens sem SQL. As novas métricas iniciais foram `DEPENDENCY_VISIBLE_OWNER_ROLES=7`, `DEPENDENCY_DISTINCT_EXTENSIONS=0`, `TOC_EXTENSION=6`, `DEPENDENCY_UNCLASSIFIED_TOC_ENTRIES=9` e `DEPENDENCY_AMBIGUOUS_TOC_OWNER_ENTRIES=12`. A saída é internamente suspeita: **não interpretar zero nomes como zero extensões**. A hipótese de parsing foi confirmada por inspeção do código: o matcher antigo exigia um proprietário após o nome da extensão. `pg_restore --list` pode emitir `EXTENSION - nome` sem campo proprietário e, pior, o nome da extensão acabava sendo incluído na contagem de owner candidates.

O V6.4.1 separa `EXTENSION` antes de analisar proprietários, interpreta entrada com ou sem campo owner, e nunca considera o nome da extensão uma role. Os testes passaram a cobrir ambos os formatos e o ensaio de dump PostgreSQL sintético agora inclui `CREATE EXTENSION pgcrypto` e exige nome EXTENSION detectado no caminho AES-GCM + pg_restore --list. **A contagem original 7 roles candidatas não estava autenticada semanticamente como sete roles reais**; só um novo relatório corrigido poderá reestimar essa contagem, ainda sujeita a outros itens ambíguos.

A falha anterior `BLOCKED_ERROR_REDACTED` foi seguida por uma autenticação bem-sucedida. Sem evidência adicional, não há atribuição conclusiva dessa falha a uma causa específica. Nenhum SQL ou dado de produção foi alterado pelos dois relatórios. Não é necessário fornecer dump em claro ou lista privada de nomes ao desenvolvedor.

## V6.4.2 — Segundo relato local, correção de coluna vazia em EXTENSION

Novo resultado do operador: backup real autenticado com sucesso (`AES_GCM_TAG_AUTHENTICATED=YES`), catálogo 919/919 intacto, 6 entradas `TOC_EXTENSION`, mas contador de nomes novamente zero. Alteração de métricas de `UNCLASSIFIED=9→15` e `AMBIGUOUS_OWNER=12→6` após V6.4.1 confirma que as 6 entradas passaram para o ramo de parsing de extensões mas ainda não casaram no matcher. Hipótese técnica principal: `pg_restore --list` imprime a coluna owner vazia como espaços à direita; V6.4.1 não normalizava whitespace à direita.

O V6.4.2 agora normaliza apenas a extremidade direita (`trimEnd()`), preserva dados entre colunas e interpreta extensões sem campo owner, sem considerar o nome de extensão como role. Foi criado teste com coluna final vazia em várias formas (`spaces` e `tab`) e verificação direta sobre o módulo do GitHub mostrou 6 entradas e 6 nomes distintos para um fixture; isso ainda precisa de confirmação no **backup verdadeiro**.

**Mudança fail-closed:** um campo EXTENSION de formato desconhecido gera `EXTENSION_TOC_FORMAT_UNSUPPORTED` e jamais `DEPENDENCY_DISTINCT_EXTENSIONS=0` com `PG_RESTORE_CATALOG=PASS`. A integridade criptográfica e o inventário original permaneceram válidos em todas as tentativas; o bug estava exclusivamente na classificação secundária de dependências. Nenhuma SQL foi executada.

# Guardian V5.7 — Catálogo canônico e detecção de divergências reais de permissões

## Escopo entregue

`scripts/GuardianV57-CanonicalCatalog.sql` é uma consulta PostgreSQL **somente leitura** que retorna linhas normalizadas e ordenadas de um schema alvo: schema e owner, ACL de schema, tabelas e owners, colunas/tipos/defaults, permissões de tabelas, índices, constraints, políticas RLS, DEFAULT ACLs, funções e triggers. Não recupera dados e não é um dump global de roles. Não use o SQL em produção nesta etapa.

`scripts/GuardianV57-CompareCatalog.mjs` confere dois arquivos de catálogo produzidos em ambientes isolados. Compara SHA-256 das representações semânticas ordenadas e informa somente contagens por tipo e 16 caracteres de cada fingerprint; **não imprime** nomes, SQL, caminhos, roles ou conteúdo. Uma diferença semântica detectada, mesmo com contagens iguais, retorna exit 2. É obrigatório obter as duas entradas de origens independentes de verdade: a ferramenta não verifica a origem desses arquivos.

## Testes

- `.github/workflows/guardian-v56-owner-acl-restore.yml` foi ampliado: após `pg_restore` de dump **sintético** com GRANT, DEFAULT ACL, owner e RLS, gera o catálogo na origem e no destino e exige fingerprints idênticos; em seguida, revoga um GRANT no destino e exige que o fingerprint mude.
- `.github/workflows/guardian-v57-catalog-compare.yml` testa no Windows e Linux os estados correto, mudança de ACL sem mudança de contagem, desordem, categorias desconhecidas e conteúdo binário bloqueado.
- O teste de isolamento só conecta containers descartáveis próprios e não envolve o `.r62db` verdadeiro, senhas, tabelas ou dados pessoais do TaxiRadar.

## Segurança e limitações

**Atenção: arquivos intermediários do SQL podem conter nomes de tabelas, roles, SQL de funções e outras informações privadas.** Na utilização real devem existir somente em volume temporário protegido com permissões restritivas ou em memória, nunca no Git, cloud, clipboard, stdout ou logs. A saída do comparador é sanitizada, mas os arquivos de entrada não são.

A equivalência canônica é forte para os atributos cobertos, mas não prova dados de linhas, todas as flags de roles globais, membership de roles, extensões gerenciadas, Storage, configurações Supabase, Edge Function API, Web, secrets e funcionalidades da aplicação. Ainda há objetos do TOC não classificados e a divergência de escopo 77 versus 76 tabelas continua precisando de revisão.

## Próxima barreira antes da restauração do banco verdadeiro

A meta do Guardian não é só `pg_restore` sair com código zero. A restauração real precisará de globals oficiais, compatibilidade de extensões, isolamento de rede de funções/triggers, GCM validado, execução transacional sem omitir permissões, comparação canônica contra o backup original, conferência de dados e smoke tests do TaxiRadar. Não mexer nos quatro containers CLEAN6 conhecidos, em produção ou no DNS. A recuperação completa em 4–6 horas só será declarada após um ensaio cronometrado.
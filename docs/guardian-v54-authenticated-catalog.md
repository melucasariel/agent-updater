# ROTA62 Guardian V5.4 — inspeção autenticada do catálogo PostgreSQL sem executar SQL

## Prova real já estabelecida pelo operador

Em Windows, três arquivos `R62DB02` são cópias idênticas de um snapshot, SHA-256 `35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA`, 5.287.976 bytes cada. O V5.3 do usuário **validou a senha e a autenticação AES-GCM**: `AES_GCM_TAG_AUTHENTICATED=YES`, plaintext `PGDMP`, 5.287.733 bytes, SHA-256 plaintext prefixo `EA995E37864FF769`. Nenhum arquivo plaintext foi criado, nenhuma operação SQL executada.

## Entrega V5.4

- `scripts/GuardianV54-ArchiveCatalog.mjs` repete a verificação integral do SHA externo e da tag AES-GCM antes de passar qualquer plaintext para `pg_restore --list`; o segundo streaming autentica novamente, em memória, e transmite o `PGDMP` para container PG17 descartável com `--network none`, `--read-only`, usuário sem privilégios, sem capacidades Linux, com no-new-privileges, limite de CPU, RAM e processos, sem portas ou volumes, sem SQL e sem rede externa.
- O resultado contém somente número de itens do catálogo e contagens por tipo de objeto (`TABLE`, `TABLE DATA`, `POLICY`, `INDEX`, `ACL`, `EXTENSION`, etc.). Nunca inclui nomes, roles, dados, caminhos, senha ou logs brutos no clipboard.
- O Docker precisa estar no contexto **local** `default` ou `desktop-linux` com endpoint npipe/Unix e ter a imagem `postgres:17` já carregada. Sem essa condição, bloqueia antes de solicitar a senha. Nenhuma imagem é baixada automaticamente.
- `scripts/Invoke-GuardianV54-Catalog.ps1` busca localmente o ciphertext pelo SHA-256 conhecido, chama o verificador de forma interativa e coloca no clipboard somente relatório sanificado. Uma tentativa inválida não executa restore.
- Os testes CI Linux geram um **pg_dump custom real com dados sintéticos** e verificam a extração segura de seu catálogo, políticas RLS e índices; o Windows testa sintaxe, formatos e recusa de execução não autorizada. Sem uso de dados ou senhas reais nos workflows.

## Não confundir estados

`R62DB02` autenticado **não equivale** a dados restaurados. `pg_restore --list` lista metadados do arquivo e não prova que suas roles, extensões e recursos externos estão disponíveis ou que os dados sejam recuperáveis. As 76 tabelas observadas nos bancos CLEAN6 provisórios não devem ser confundidas com quantidades de itens do TOC sem conferir escopo.

### Critérios para o V5.5 — restauro verdadeiro em ambiente isolado

1. Resultado V5.4 do catálogo original, incluindo types como `EXTENSION`, `ACL`, `DEFAULT ACL` e `TABLE DATA`.
2. Captura segura e validação de roles oficiais e extensões necessários **antes** de executar qualquer SQL, em ambiente que não possua segredos/callbacks/credenciais de produção.
3. Restaurar sem `--no-owner`/`--no-privileges`, ou aplicar correções equivalentes formalmente testadas; falhar fechado se owner/ACL divergirem da referência original.
4. Validar RLS, funções, triggers, registros de linhas com contagens seguras e dependências, sem expor dados pessoais.
5. A recuperação Web/API/Storage e medição end-to-end RTO 4–6h continuam pendentes até ensaio completo.

**Operação V5.4 não descriptografa em disco nem altera os quatro containers do usuário.**
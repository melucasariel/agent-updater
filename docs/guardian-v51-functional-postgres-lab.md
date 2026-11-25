# ROTA62 Guardian V5.1 — primeiro restore PostgreSQL 17 funcional em laboratório

## Escopo implementado

`scripts/GuardianV51-DisposablePgRestore.mjs` aceita um **pg_dump custom PostgreSQL sintético já descriptografado** em pasta de laboratório marcada, valida o SHA256 esperado, verifica o cabeçalho `PGDMP`, exige imagem `postgres:17` já disponível no Docker, cria network `--internal`, volume e container descartáveis com nomes aleatórios, faz `pg_restore --single-transaction --exit-on-error`, confirma versão PG17 e número de tabelas em SQL `READ ONLY`, e exclui os recursos criados. O teste real de integração CI gera um dump contendo uma tabela, índice e política RLS em PG17, restaura em outro container PG17 isolado e confirma a restauração.

### O que isto NÃO faz

- **Não** abre ou descriptografa o `.r62db` do usuário, não toca nos quatro containers CLEAN6 existentes.
- **Não** conecta a Supabase, Cloudflare, produção, DNS ou redes externas.
- **Não** restaura Web/API/Storage/secrets; não afirma recuperação funcional de aplicativo.
- **Não** confirma equivalência de owners/ACLs/roles de backups Supabase reais; se um backup depende de roles não presentes ou extensões, pg_restore falha, e o ambiente de teste é descartado. Um restaurador Supabase real deve tratar as roles e extensões de maneira reproduzível e testada.
- **Não** configura cron, backup automático nem publicação. Meta RTO 4–6 horas permanece não comprovada.

### Aviso obrigatório

`pg_restore` executa comandos SQL do dump e pode rodar funções de inicialização e código potencialmente perigoso com privilégios de banco. **Use somente arquivos sintéticos produzidos pelo próprio teste e em ambiente sem Docker socket, redes/volumes/credenciais de produção.** Isolamento de rede não impede efeitos dentro do host Docker se ele estiver mal configurado. Não execute esse programa com dumps arbitrários.

### Laboratório e sintaxe

Crie uma pasta exclusiva fora da produção, contendo arquivo marcador `.rota62-guardian-lab-only` com `ROTA62_OFFLINE_LAB_V1` seguido de newline. Depois de gerar um fixture com pg_dump -Fc, execute com PowerShell no checkout local verificado:

~~~powershell
$lab='C:\R62_SINTETICO_LAB'; $dump=Join-Path $lab 'fixture.dump'; $hash=(Get-FileHash -LiteralPath $dump -Algorithm SHA256).Hash
node .\scripts\GuardianV51-DisposablePgRestore.mjs --mode plan --lab-root $lab --fixture-dump $dump --fixture-sha256 $hash --expected-tables 1
node .\scripts\GuardianV51-DisposablePgRestore.mjs --mode exercise --lab-root $lab --fixture-dump $dump --fixture-sha256 $hash --expected-tables 1
~~~

`plan` não cria rede, container ou volume. `exercise` inicia e encerra apenas recursos temporários de sua autoria. A consulta de catálogo informa somente quantidade de tabelas e PostgreSQL major, nunca dados pessoais. Logs de stdout não incluem dump, caminhos privados, passwords ou queries com dados.

### Próxima entrega crítica do produto

1. Adaptador seguro para descriptografar backup `.r62db` original **localmente**, sem imprimir senha, e restaurar arquivo `PGDMP` em ambiente separado.
2. Restaurar roles, owners e ACLs de forma determinística, comparando com referência independente; preservar funções e RLS.
3. Restaurar Storage/Web/API com configuração de endpoints fictícios e testes HTTP sob rede comprovadamente isolada.
4. Gerar relatório de ensaio integral cronometrado, com hash do backup e versão testada e sem secrets; publicar apenas após aprovação separada.

**Resultado de testes automatizados é evidência exclusivamente de fixture sintético, nunca do TaxiRadar real.**
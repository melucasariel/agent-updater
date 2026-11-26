# Guardian V5.3 — AES-GCM autenticado com código original identificado

## Evidência de origem

Foi encontrado no arquivo fornecido pelo operador `ROTA62_GUARDIAN_CODIGO.zip` o arquivo `SCRIPTS\backup-postgres.mjs`, 30.331 bytes, SHA-256 `4DCBFC4B10F072AB3D1D19B5962C3083E0273E9B5AA5FACB44BB097BD38ABB7F`. A auditoria estática identificou a versão v1.4.4 e o envelope preciso: `R62DB02\n` (8 bytes); length big-endian de 4 bytes; cabeçalho JSON até 4.096 bytes; scrypt N=32768,r=8,p=1, chave 32 bytes; AES-256-GCM com nonce de 12 bytes; AAD = cabeçalho integral incluindo magic e length; 16 bytes de tag no fim; conteúdo esperado `PGDMP`. Nenhum secret foi copiado do projeto original para GitHub.

## Novo código

`scripts/GuardianV53-AuthenticateR62DB.mjs` usa o formato acima para autenticar o arquivo criptografado com senha digitada exclusivamente no terminal Windows. Reconfere SHA-256 externo antes/depois, exige tag GCM válida, valida `PGDMP` **após** finalizar a autenticação criptográfica e descarta a saída plaintext apenas em memória. Não cria dump em disco, não acessa Docker, PostgreSQL, Supabase, Cloudflare, DNS ou secrets de produção. O relatório é intencionalmente limitado à autenticação e ao hash parcial dos bytes desencriptados; nunca imprime senha, SQL, dados ou caminhos.

`scripts/Invoke-GuardianV53-Authenticate.ps1` oferece um fluxo de um único Enter: procura os arquivos cifrados conhecidos por SHA, chama o Node interativamente para senha sem eco (exibindo apenas asteriscos), recolhe um relatório SANITIZADO gravado temporariamente e copia o resultado para clipboard, removendo o relatório temporário. **O relatório temporário não contém plaintext.** Se executar na automação sem TTY, o verificador bloqueia.

## Regressões com fixtures sintéticos

`scripts/test-GuardianV53-AuthenticateR62DB.mjs` fabrica um envelope idêntico ao v1.4.4 com dados artificiais, verifica autenticação válida, rejeita senha incorreta, SHA incorreto, AAD alterado, dados alterados, tag alterada, truncamento e plaintext fora de `PGDMP`. Linux e Windows CI. Nenhum backup verdadeiro ou senha do operador é usado.

## Distinções obrigatórias

- `AES_GCM_TAG_AUTHENTICATED=YES` prova somente a autenticação de **aquele ciphertext com a senha local**, não comprova restauração, conteúdo de dados, owners, ACLs, Storage, site, API ou integridade independente da origem.
- `R62DB02` ainda contém histórico de `pg_restore --no-owner --no-privileges` no código original; o novo módulo **não chama este restore antigo**.
- 3 cópias de 5.287.976 bytes, com mesmo SHA, continuam um único ponto histórico de recuperação.
- O alvo de recuperação 4–6 horas permanece **não comprovado** até recuperação completa e verificação funcional.

## Próximo release

Após autenticação local bem-sucedida do `.r62db` real, desenvolver fluxo de streaming para PostgreSQL 17 descartável com preflight e preparo de roles oficiais, owners, ACLs, DEFAULT ACLs, funções e RLS, comparação com proveniência confiável e zero vazamento de credentials/dump. Esse módulo NÃO restaura banco de dados e não permite cutover em produção.
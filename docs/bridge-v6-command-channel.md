# ROTA62 Bridge V6 — contrato para comandos remotos (proposta, não ativo)

Estado: **NÃO INSTALADO / NÃO AUTORIZADO PARA EXECUÇÃO REMOTA**.

## Objetivo
Permitir que ChatGPT envie solicitações *estruturadas e limitadas*, via GitHub, a um agente Windows explicitamente configurado, com retorno de resultados sanitizados. O repositório atual é público e dedicado a distribuição de updates; mensagens públicas não podem carregar senha, diagnóstico sensível, identificadores pessoais, tokens, strings de conexão ou backups.

## Interface proposta
- Tipos permitidos: `SELFTEST`, `AUDIT_PREFLIGHT` (somente leitura), `STOP` (somente o agente).
- `SEMANTICS` permanece DESABILITADO até assinatura/hash do script e aprovação explícita da auditoria.
- Mensagem: `protocol_version`, `request_id`, `command`, `issued_at`, `expires_at`, `nonce`, `signature`.
- O agente deve verificar assinatura por chave pública previamente instalada, expiração, replay, lista fixa de ações, versão do protocolo e origem.
- GitHub Issues e arquivos no branch não devem ser considerados comandos executáveis por si.
- Nunca executar código PowerShell arbitrário, `Invoke-Expression`, `curl | iex`, anexos de Issues, nem conteúdo de comentários.
- Nunca usar GitHub público para enviar relatórios locais. Retorno exige canal privado autenticado com expurgo, política de retenção, validação do destinatário e consentimento.

## Condições para ativação
1. Inspecionar o Bridge V6 realmente instalado e verificar se implementa polling do canal e quais comandos aceita.
2. Implementar autenticação de solicitações, limites, logging seguro e botão local de desligamento.
3. Testar `SELFTEST` sem alterar Docker, PostgreSQL ou arquivos de produção.
4. Só então permitir uma ação do ChatGPT que produza solicitação; retornar resultado na conversa requer mecanismo separado e testado. **Publicar arquivo no GitHub não envia automaticamente resultado para esta conversa**.

## Proteções permanentes
- Deploy/restore/prod database requer autorização explícita e verificação forte.
- Chave privada fica fora do GitHub.
- Restauração e auditoria semântica exigem `ROLLBACK` e comprovante de isolamento antes de liberar.

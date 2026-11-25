# Política de atualização segura — ROTA62 Guardian

## Escopo
Distribuir apenas o Agent Windows e recursos diagnósticos não sensíveis. Nenhum banco de dados, segredos, tokens ou dados de clientes.

## Formato de manifesto proposto (ainda não ativado)
Os nomes abaixo descrevem um **contrato a implementar e testar**, não um formato já compatível com o Agent v3.0:

```json
{
  "schema_version": 1,
  "version": "0.0.0",
  "package_url": "https://github.com/OWNER/REPO/releases/download/TAG/PACKAGE.zip",
  "package_sha256": "64 caracteres hexadecimais",
  "min_agent_version": "3.0.0"
}
```

A assinatura criptográfica deve cobrir os bytes canônicos do manifesto. A URL deve ser HTTPS, de domínio e caminho autorizados, e não permitir redirecionamento para origem inesperada. A verificação deve usar **chave pública previamente fixada no Agent**; publicar uma chave pública neste repositório, por si só, não estabelece confiança.

## Aprovação antes de ativar
- Revisar o contrato exato do atualizador v3 instalado.
- Configurar chave pública de confiança e proteger a chave privada fora do repositório.
- Testar assinatura válida, inválida, pacote adulterado, downgrade, timeout, interrupção e rollback.
- Confirmar que o Agent não executa conteúdo de atualização antes das verificações.
- Somente depois ativar checagem automática de Releases.

## Operações
Manter logs locais com redação de informações sensíveis. Não coletar segredos nem usar o ambiente TaxiRadar de produção para testar atualização.

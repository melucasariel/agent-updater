# Próxima ação no Windows: estabelecer confiança local

Estado confirmado: Agent v3.0 instalado; `UPDATE_STATUS` reportou `ATUALIZACAO_REMOTA=DESATIVADA_SEM_REPOSITORIO_OU_CHAVE`.

## Uma única inicialização local (PowerShell)

Abra o Windows PowerShell com **o mesmo usuário que executa o Guardian**. Execute:

```powershell
$ErrorActionPreference='Stop'
$f=Join-Path $env:TEMP 'GuardianTrustBootstrap.ps1'
try {
  Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/melucasariel/agent-updater/main/scripts/Bootstrap-GuardianTrust.ps1' -OutFile $f -UseBasicParsing
  $expected='AFB36C22F6AEEBE5C126B0FE213CF05D89C3DEB02193D3BD2CBEE8B695D8B4A2'
  if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash -cne $expected) { throw 'SHA256 divergente: BLOQUEADO' }
  & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f
  if ($LASTEXITCODE -ne 0) { throw 'Bootstrap nao concluido' }
} finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
```

A execução baixa um script temporário, confere seu SHA256 e somente então roda localmente. O script gera uma chave privada RSA local protegida via DPAPI CurrentUser; **não publica segredos, não habilita atualizações nem modifica Docker/SQL**. Não compartilhe arquivos `signing-private.dpapi` ou qualquer XML de chave privada.

O texto seguro para reportar após sucesso é:

```text
GUARDIAN_TRUST_BOOTSTRAP=OK; DPAPI_KEY=LOCAL_ONLY; REMOTE_UPDATE=UNCHANGED
```

## Por que ainda há uma ação manual

O Agent v3.0 reconhece `GUARDIAN:UPDATE_STATUS` e `GUARDIAN:UPDATE_CHECK`, mas **não** reconhece comandos para gerar ou instalar nova chave de confiança. Não é possível adicionar esse comando remotamente sem antes estabelecer um canal de confiança.

## Pendências

1. Corrigir proteção anti-downgrade e rollback automático do atualizador.
2. Implementar e testar provisionamento seguro da chave pública previamente fixada no Windows.
3. Publicar primeira Release assinada de teste e validar no laboratório descartável.
4. Só então habilitar instalação automática de versões futuras.

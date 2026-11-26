# Guardian V4 — coverage gate (integridade de 7 componentes)

Implementado: `scripts/GuardianV4-Coverage.mjs` com `--mode plan` e `--mode verify`. O módulo funciona offline, não faz consultas à produção, não altera Docker, não descifra backups e não transfere conteúdo ao GitHub. Produz contagens e fingerprints compactos, sem imprimir caminhos ou nomes.

**Limite explícito:** esta etapa não cria um backup completo; exige sete snapshots já produzidos e protegidos. Aprovar o gate não prova recuperação real, que requer restaurar em ambiente isolado e testar API/Web.

Componentes obrigatórios: `database` (arquivo `.r62db` criptografado com SHA-256 confiável), `web` (diretório de fontes/deploy), `api` (diretório de código e dependências), `storage` (diretório snapshot; se vazio, criar marcador sintético assinado por processo de captura), `dns` (arquivo exportado), `config` (configuração não secreta) e `secrets-vault` (referência/cofre criptografado offline).

O arquivo de configuração deve ficar **fora** do repositório público, fora de diretórios enviados à nuvem e sem chaves em texto puro. Formato:

```json
{
  "format": "r62-guardian-v4-input-1",
  "components": {
    "database": {"kind":"file","path":"C:\\PRIVATE\\backup.r62db","sha256":"COLOCAR_SHA256_64_CARACTERES"},
    "web": {"kind":"directory","path":"C:\\PRIVATE\\web"},
    "api": {"kind":"directory","path":"C:\\PRIVATE\\api"},
    "storage": {"kind":"directory","path":"C:\\PRIVATE\\storage"},
    "dns": {"kind":"file","path":"C:\\PRIVATE\\dns.json"},
    "config": {"kind":"file","path":"C:\\PRIVATE\\config.json"},
    "secrets-vault": {"kind":"file","path":"C:\\PRIVATE\\vault.age"}
  }
}
```

Executar no checkout local verificado:

```powershell
node .\scripts\GuardianV4-Coverage.mjs --mode plan --config C:\PRIVATE\guardian-input.json
node .\scripts\GuardianV4-Coverage.mjs --mode verify --config C:\PRIVATE\guardian-input.json
```

Segurança: rejeita symlinks, arquivos inválidos, diretórios vazios, objetos inesperados e digest SHA-256 divergente do arquivo criptografado. O SHA-256 do backup deve vir de fonte independente; uma cópia idêntica do mesmo snapshot não é outro ponto no tempo. Nunca usar `CI` com backup, secrets ou dados reais.

Próxima entrega: capturador com integrações autorizadas e manifestos atômicos, criptografia autenticada do pacote completo, storage offsite e ensaio completo de recuperação. O gate atual reporta intencionalmente `BACKUP_RECOVERY_VERIFIED=NO`.
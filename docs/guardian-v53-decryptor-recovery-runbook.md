# Guardian V5.3 — retomada do descriptografador original (NÃO executar ainda)

## Resultado conhecido e confirmado no Windows

- Arquivo `R62DB02` reconhecido, SHA-256 `35FCCCD54DB5D42729EFF95227133D0875D6FC7F730C881BA486F87F46F038EA`, 5.287.976 bytes.
- Três cópias bit a bit idênticas, um único ponto de recuperação; arquivo não foi descriptografado ou restaurado pelo V5.2.
- Restauros PG17 sintéticos no V5.1 aprovados; não equivalem a restauração real do TaxiRadar.

## Ingestão V5.3

`scripts/Invoke-GuardianV53-LegacyRestoreIntake.ps1` percorre raízes locais com filtro exato `*backup-postgres*.mjs` e examina apenas tamanho, SHA-256 e marcadores booleanos de código (scrypt, AES-GCM, pg_restore e flags que omitem owner/ACL). Nunca executa os arquivos encontrados, não pede senha e não acessa produção, Docker ou backup. O relatório é sanitizado e copiado automaticamente para clipboard.

O código legado, se encontrado, exige auditoria de origem e SHA, revisão de sua API e execução unicamente sob sandbox local com senha digitada sem eco. O texto estático com marcadores não certifica que a implementação realmente descifra o arquivo. Não reimplementar `R62DB02` sem fonte completa e testes conhecidos.

### Próximas condições para restaurar backup verdadeiro

1. Recuperar o source original `backup-postgres.mjs`, identificar formato e comparar hashes/versão com histórico, sem executar sua função de restore de produção.
2. Isolar a extração em ambiente sem egress, sem tokens/cloud secrets, sem rede publicada e sem acesso a volumes/containers do TaxiRadar; autenticação de GCM precisa falhar fechada, sem persistir plaintext.
3. Obter roles em pacote oficial e restaurar funções/ACLs/default ACL em destino novo, recusando flags `--no-owner` / `--no-privileges` quando não há alternativa testada.
4. Comparar identidade de owners e ACLs contra referência independente obtida do backup original, não os quatro bancos já modificados.
5. Restaurar serviço Web/API/Storage e testar login e corrida sintética sem callbacks de produção. Medir RTO end-to-end em 4–6h.

**Nenhuma mudança de produção ou decrypt real é autorizada automaticamente por este commit.**

### Como executar localmente em checkout revisado

```powershell
& .\scripts\Invoke-GuardianV53-LegacyRestoreIntake.ps1
```

Resultado seguro não inclui nomes e caminhos de arquivos, passwords, tokens, código bruto ou qualquer conteúdo privado.
# ROTA62 Guardian V4 — operação manual antes de atualizações, recuperação em até 4–6 horas

**Decisão do proprietário (2026-11-25): não agendar backups automaticamente.** Os backups devem ser disparados manualmente, especialmente antes de atualizações. O objetivo do plano de recuperação (RTO) é 4–6 horas após falha. RTO ainda não demonstrado em teste ponta a ponta.

## Componentes disponíveis

- `scripts/GuardianV4-Coverage.mjs`: valida integridade de 7 componentes locais já exportados; não captura nem publica.
- `scripts/GuardianV4-ManualRecoveryGate.mjs`: implementa dois modos de relatório: `--action pre-update` exige os 7 componentes e arquivo de banco criptografado com hash esperado e idade máxima configurável; `--action restore-readiness` exige além disso declaração de teste de recuperação associado ao mesmo hash. Não concede autorização automática para deploy.
- O antigo `scripts/Audit-Clean6FourWay.mjs` continua disponível para catálogo PG17 em laboratório descartável; não substitui recuperação ponta a ponta.

## Comandos (Windows, checkout revisado)

Depois de gerar os snapshots com ferramentas oficiais, preencha um arquivo privado `guardian-input.json` conforme `docs/guardian-v4-coverage.md` e execute:

```powershell
node .\scripts\GuardianV4-ManualRecoveryGate.mjs --action pre-update --config C:\PRIVATE\guardian-input.json --max-age-hours 24
node .\scripts\GuardianV4-ManualRecoveryGate.mjs --action restore-readiness --config C:\PRIVATE\guardian-input.json --test-report C:\PRIVATE\rehearsal-evidence.json
```

Um resultado `PRE_UPDATE_VERIFICATION_GATE=PASS` apenas informa que arquivos existem, têm hashes compatíveis e que o arquivo `.r62db` tem data de modificação recente. **Não prova que foi capturado antes da atualização desejada, tampouco libera um deploy.** O relatório intencionalmente traz `PUBLISH_AUTHORIZED=NO`.

O relatório opcional `rehearsal-evidence.json` tem formato `{ "format":"r62-guardian-rehearsal-evidence-v1", "outcome":"PASS", "durationMinutes":180, "completedUtc":"2026-11-25T00:00:00Z", "backupSha256":"<SHA256 de 64 caracteres>" }`. Esses dados são uma declaração local não autenticada, não substituem telemetria assinado e smoke tests reais. O sistema não afirma ter medido RTO até que um restaurador confiável produza essas evidências automaticamente.

## Criterios obrigatórios de aceite para a meta 4–6 h

1. Snapshot geral consistente de banco, roles, ACLs, web, API, Storage, DNS e configurações, com cofre secreto separado e independentemente recuperável.
2. Manual `Criar Backup` e aprovação explícita antes de publicar; em falha, bloquear a publicação e preservar backup anterior.
3. Restaurar em projeto novo com defaults, funções e política RLS idênticos ao backup; sem scripts SQL manuais improvisados.
4. Simular autenticação, corrida fictícia e funções principais sem callbacks à produção; medir o RTO até HTTPS e app funcional.
5. Validar cópia offsite e procedimento de recuperação do cofre caso o computador seja perdido.

Nenhum backup foi automaticamente agendado ou executado por esta alteração. Nenhuma rotina de produção foi alterada.
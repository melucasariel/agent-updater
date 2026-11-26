# ROTA62 Guardian V6.0 — assinatura independente e cadeia de custódia do Backup Geral

## Atualização V6.0 — preparação manual atômica antes da assinatura

Acrescentado `scripts/GuardianV60-PrepareOfflineBundle.mjs`, que recebe uma configuração local com exatamente oito caminhos de arquivos **já capturados**, um SHA-256 esperado para cada um e um diretório de laboratório marcado como offline. Ele confere os oito hashes antes de copiar, monta sete arquivos na pasta temporária, reconfere origem e destino, mantém o cofre fora do pacote e publica a nova pasta por rename sem sobrescrever.

O formato de entrada é `r62-guardian-v60-prepared-files-1` com `captureId`, `release` e `components.{database,web,api,storage,dns,config,globals,secrets-vault}.{path,sha256}`; cada path é absoluto, não pode ser symlink nem estar dentro do laboratório. A entrada `database` exige o cabeçalho externo `R62DB02`. Os oito arquivos de entrada precisam ter sido produzidos **antes**, com ferramentas oficiais; o programa não captura sites ativos ou objetos Storage.

Ordem modular: **Preparar pacote offline → Assinar manifesto com chave privada criptografada fora do pacote → Verificar assinatura com chave pública confiável independente → Avaliar pré-requisitos e testar restauração**. A simples assinatura e a cópia não permitem declarar o aplicativo recuperável.

A atomicidade refere-se à publicação por rename e tratamento de falhas de software; não substitui cópias externas, fsync/durabilidade em queda de energia nem consistência transacional entre serviços. Não usar em produção sem completar os demais gates.

---
## O que a primeira entrega implementa

Após o V5.9, o Guardian tem sete componentes identificados e um stage offline de seis componentes, mas os manifests eram apenas SHA256 *auto-declarados* — qualquer pessoa que alterasse um arquivo poderia recalcular o manifesto. O V6.0 implementa um **manifesto separado com assinatura digital Ed25519**, desde que a chave pública de verificação e seu **SHA-256 completo** tenham sido entregues e confiados ao operador **por um canal independente**.

Dois scripts compõem a entrega:

- `scripts/GuardianV60-SignPreparedBundle.mjs`: operação **MANUAL** sobre sete artefatos já capturados em uma pasta offline, com uma chave privada Ed25519 **criptografada PKCS#8** fora do bundle; a senha da chave é solicitada no terminal sem eco. Assina byte a byte o `manifest.json` e gera `manifest.sig` sem sobrescrever arquivos existentes. Não gera/captura os artefatos de produção, não abre Docker e não executa SQL.
- `scripts/GuardianV60-SignedBundleTrust.mjs`: verifica assinatura destacada, exige chave pública confiável **fora do bundle** e seu fingerprint completo de SHA-256 previamente confiado (`--expected-key-sha256`), bloqueia path traversal e symlink, confere o hash e o tamanho de **sete componentes** de dentro do pacote e o **oitavo componente — cofre de secrets — armazenado separadamente**. Não usa a senha do backup do banco. Não lê conteúdo SQL ou secrets para execução.

## Estrutura esperada para o bundle preparado

```text
bundle/
  database/snapshot.bin
  web/snapshot.bin
  api/snapshot.bin
  storage/snapshot.bin
  dns/snapshot.bin
  config/snapshot.bin
  globals/snapshot.bin
  manifest.json             (assinado)
  manifest.sig              (Ed25519 detached)

trusted-offline/
  trusted-public.pem         (FORA do bundle)
  encrypted-private.pem      (FORA do bundle e preferencialmente offline)
  vault.enc                  (FORA do bundle)
```

Os caminhos `snapshot.bin` são um **contrato de empacotamento**, não uma instrução para renomear arbitrariamente um diretório existente ou concluir que seus bytes podem ser implantados. O Backup Geral deve primeiro capturar todos os componentes no formato apropriado. O arquivo de globals, em particular, deve ser produzido e autenticado de forma independente e auditado antes de executar qualquer SQL.

## Modelo de confiança

- **SHA-256**: detecta alterações nos bytes depois de calculada a referência.
- **Assinatura Ed25519**: prova correspondência do manifesto com a chave privada da identidade aprovada pelo operador. A chave pública precisa ser confiada **fora do pacote que será verificado**.
- **Não comprovado por assinatura:** que os oito artefatos foram extraídos do mesmo momento do sistema, que os secrets podem ser restaurados, que `globals.sql` é seguro, que as extensões são compatíveis ou que o aplicativo funcionará.
- **Timestamp**: campo declarativo no manifesto; não representa carimbo de tempo assinado por autoridade independente.
- **Chave privada**: nunca enviar ao GitHub, ao ChatGPT ou aos logs. O backup pode ser verificado sem revelar ou usar a chave privada.

## Testes integrados

`.github/workflows/guardian-v60-signed-trust.yml` verifica signature, key mismatch, manipulação do manifesto, alteração do arquivo e cofre externo, e rejeita confiança se o trust anchor estiver dentro do bundle.

`.github/workflows/guardian-v60-signer.yml` usa apenas credenciais e arquivos **sintéticos** para provar assinatura usando chave privada criptografada, recusa de senha incorreta, proibição de sobrescrita e falha diante de adulteração dos artefatos.

## Situação do projeto

**Guardian V6.0: assinatura e verificação do pacote implementadas em módulos offline, mas o fluxo de captura completa do TaxiRadar e o restore real ainda não estão concluídos.**

Dependências necessárias para avanço real: capturar globals do projeto original com proveniência, validar extensões e ACLs; testar os componentes Web/API/Storage/DNS/config e vault em ambiente novo; realizar restore do `.r62db` autêntico em PostgreSQL descartável seguro; comprovar RTO 4–6 horas num ensaio cronometrado.

As operações planejadas continuam: **Criar Backup · Testar Recuperação · Recuperar Sistema**, com backup MANUAL antes das atualizações, nunca cron automático de quatro horas. A produção, DNS e containers CLEAN6 permanecem fora do escopo dessas ferramentas.

Referências: `docs/guardian-error-ledger-and-nonregression.md`, `docs/guardian-v59-sealed-recovery-and-completeness.md`.
### Proteção anti-substituição da identidade de assinatura

O verificador V6.0 exige agora `--expected-key-sha256` (SHA-256 do DER SPKI da chave pública) obtido **fora do pacote**. Ele não aceita apenas um `trusted-public.pem` que poderia ser substituído pelo mesmo invasor capaz de adulterar os arquivos. O teste de regressão tenta trocar a chave pública e força `TRUST_KEY_FINGERPRINT_MISMATCH`. Essa pinagem deve ser registrada em local independente do disco/arquivo que contém os backups; a chave privada é armazenada offline e criptografada. Nenhuma chave real foi criada ou compartilhada neste desenvolvimento.

## Ensaio integrado V6.0

A bateria `.github/workflows/guardian-v60-integrated-ceremony.yml` cobre em Windows e Linux o fluxo **preparar → assinar com private key PKCS#8 criptografada → verificar com fingerprint Ed25519 previamente conhecido → adulterar cópia assinada e recusar**. Ela usa arquivos artificiais com `R62DB02` de teste, nunca o ciphertext do TaxiRadar e nunca a senha do usuário. O snapshot de origem pode mudar depois da cópia sem alterar o pacote já assinado; alterar o próprio pacote após assinar causa `COMPONENT_HASH_MISMATCH`.

O fluxo completo ainda exige depois uma **captura consistente real de todos os serviços** (Web, API, Storage, DNS, config, globals, banco e secrets em cofre); não transformar esse módulo sintético de preparação em um “backup pronto” sem esses capturadores, sem teste de recuperação e sem prova de RTO.

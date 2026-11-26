# ROTA62 Guardian V6.1 — Inventory de versões e avaliação segura de globals

## Objetivo

Continuar o V6.0 em duas dimensões prioritárias: saber **quais versões existem de verdade**, sem confundir cópias idênticas com novas capturas; e obter sinais confiáveis **de integridade, não de execução**, de um arquivo candidato a `pg_dumpall --globals-only`, necessário para restaurar roles/owners sem `--no-owner` nem `--no-privileges`.

## 1. Histórico de pacotes assinados

`scripts/GuardianV61-SignedRecoveryInventory.mjs` aceita uma lista explícita de pastas de pacotes já preparados e assinados, com caminho para o cofre externo, chave pública Ed25519 e SHA256 de chave **conferido contra uma referência fixada fora do índice**. O módulo chama o verificador V6.0 para cada pacote, autentica a assinatura e todos os SHA256 de artefatos e produz apenas contagens, nunca caminhos, nomes, passwords ou conteúdo de arquivos.

Um índice JSON privado deve ter este formato (usar caminhos absolutos locais reais, sem escrever secrets aqui):

```json
{
  "format": "r62-guardian-v61-inventory-1",
  "entries": [
    {
      "bundleRoot": "<absolute path to a prepared signed backup>",
      "vaultFile": "<absolute path to an external encrypted vault>",
      "publicKeyFile": "<absolute path to an independently trusted Ed25519 public key>",
      "keySha256": "<full SHA256 fingerprint of trusted public SPKI DER>"
    }
  ]
}
```

Execução: `node scripts/GuardianV61-SignedRecoveryInventory.mjs --inventory <absolute-index-json-path> --trusted-key-sha256 <SHA256-FIXADO-FORA-DO-ÍNDICE>`.

**Segurança adicional:** o campo `keySha256` do índice é considerado dado NÃO confiável. Um invasor poderia alterar juntos o índice e o arquivo da chave pública. O Guardian exige o mesmo SHA-256 da chave fornecido em parâmetro separado, obtido por um canal independente, e bloqueia divergências com `UNTRUSTED_SIGNER_IN_INDEX`. Não basta copiar o hash que está no índice para a opção externa: o operador deve conservar a referência original em armazenamento separado.

Resultados: bundles com assinatura/autenticidade do manifesto verificada, hashes válidos de todos os componentes, pacotes completos distintos, cópias idênticas, quantidades de releases e identidades de chaves confiadas. Bloqueia colisão de `captureId` entre pacotes diferentes, repetição do mesmo caminho e substituição da chave assinante.

**Ressalva crítica:** o relatório agora usa `DISTINCT_ENCRYPTED_DATABASE_ARCHIVES`, e não afirma que são estados históricos distintos. Recriptografar os MESMOS dados com outro salt/nonce altera o SHA do ciphertext. Hash distinto não comprova conteúdo nem data distinta. As três cópias idênticas do único R62DB02 verdadeiro continuam apenas **uma identidade de arquivo criptografado** — e um ponto histórico identificado nesse conjunto, sem prova de backups posteriores.

Os timestamps no manifesto são declarativos e não têm carimbo de tempo independente. O programa não faz inventário automático do disco inteiro e não valida a fidelidade da restauração.

## 2. Arquivo de roles globais

`scripts/GuardianV61-GlobalRolesEvidence.mjs` analisa **somente de maneira estática** um arquivo SQL candidato e exige um SHA-256 esperado **fornecido independentemente**. Retorna contagens indicativas `CREATE ROLE`, `ALTER ROLE`, `GRANT`, `REVOKE`, presença indicativa de cláusulas de senha, SUPERUSER, BYPASSRLS, possível DO/COPY/ALTER SYSTEM e um indicador de cabeçalho pg_dumpall.

Ele **não é um parser SQL completo**, portanto `COUNT` e flags podem conter falsos positivos ou ignorar tokens escondidos em literais e comentários. A ausência de uma flag NÃO comprova que o SQL é seguro. **Nunca executar automaticamente o SQL dessa ferramenta**. Roles globais dependem do estado original Supabase, da versão PostgreSQL e da política de managed roles; o arquivo precisa de revisão independente e proveniência do mesmo snapshot real.

Execução: `node scripts/GuardianV61-GlobalRolesEvidence.mjs --globals <absolute-globals.sql> --expected-sha256 <sha256-independent-reference>`.

O output nunca mostra SQL original, nomes de contas/roles, salts, hashes de senha ou paths. Não acessa a produção nem Docker. O resultado deve manter `SOURCE_PROVENANCE_INDEPENDENTLY_PROVEN=NO`, `GLOBALS_SQL_SEMANTICALLY_VALIDATED=NO` e `READY_TO_APPLY_GLOBALS=NO` até revisão real.

## 3. Testes automatizados

`.github/workflows/guardian-v61-signed-inventory.yml`: teste Windows e Linux com três pacotes completos sintéticos assinados; dois contêm o mesmo arquivo criptografado e o mesmo conjunto geral de artefatos, um contém Web diferente. Exige contar um só arquivo ciphertext distinto, dois pacotes distintos e duas labels de versão, além de bloquear signer e captureId falsificados.

`.github/workflows/guardian-v61-global-roles.yml`: testa relatório sanitizado com SQL artificial que contém cláusula de senha falsa, role grants, alterações, DO, adulteração de SHA e arquivo binário. Nenhuma conta ou credencial real e nenhum SQL executado.

## 4. Prioridades que continuam pendentes

1. **Criar de verdade os sete componentes** a partir do TaxiRadar Web, Edge/API, PostgreSQL, Storage, DNS, configuração e roles oficiais, com secrets em cofre externo. O empacotador V6.0 só reúne artefatos existentes.
2. Associar cada release e ponto de recuperação a evidências de captura consistente e timestamp confiável, distinguindo cópias de novos estados.
3. Restaurar o `R62DB02` verdadeiro somente em um destino PostgreSQL novo, isolado, com globals e extensões oficiais revisados, preservando ACL/DEFAULT ACL e RLS; sem tocar nos quatro CLEAN6.
4. Restaurar site, API, Storage, secrets e DNS em staging. Executar ensaio cronometrado antes de declarar RTO 4–6h comprovado.

Backup permanece **manual antes das atualizações**. Não criar cron de quatro em quatro horas. Produção não foi modificada.
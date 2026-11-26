# ROTA62 Guardian V5.9 — Ciphertext imutável e gate do Backup Geral

Data: 2026-11-25. Objetivo: interromper condições de corrida antes de abrir caminho para restore do backup real.

## Correção de segurança descoberta na auditoria do V5.8

No protótipo V5.8, havia duas leituras do arquivo cifrado: uma para autenticar o AES-GCM, seguida de uma segunda que transmitia o texto para `pg_restore`. Se o arquivo fosse alterado entre as passagens, SQL poderia começar a executar antes de a segunda passagem chegar ao final e validar a tag. A transação mitigava vários erros, mas **não substituía** a garantia de autenticar exatamente os bytes que seriam usados para restaurar.

O V5.9 substitui o segundo streaming por um snapshot cifrado **imutável na memória**, verifica SHA-256 e tag AES-GCM na mesma cópia, **completa a autenticação antes de iniciar `pg_restore`**, então envia os bytes autenticados para PostgreSQL sintético descartável. Os buffers que contêm key, plaintext e ciphertext são zerados ao concluir ou falhar. Nenhum plaintext é escrito em disco. Esse mecanismo ainda limita tamanho a 64 MiB e é um **teste de laboratório com dados sintéticos**, não a arquitetura final para backups reais maiores. A saída indica `IMMUTABLE_CIPHERTEXT_SNAPSHOT=YES` e `MEMORY_BUFFERS_WIPED=YES`.

### Limitações residuais a tratar antes do uso real

- Docker pode ler uma configuração de daemon/contexto adicional; nunca confiar só no nome de imagem ou container. V5.8 já exige label sintética e rede Docker interna. Proibir publicação, bind mounts e credenciais reais.
- `pg_restore` executa SQL do dump. A restauração de um archive não confiável é execução de código privilegiado; testes somente em infraestrutura própria e descartável.
- Mesmo com transação, extensões, funções e integrações externas podem ter efeitos. Necessário isolamento total e revisão de globals/roles de origem antes de qualquer restore real.
- Uma cópia AES-GCM autenticada prova autenticidade perante a chave, **não** prova ausência de dados de clientes vazados nem funcionalidade das APIs.

## Gate independente V5.9 para Backup Geral

`scripts/GuardianV59-DisasterEvidence.mjs` recebe configuração já preparada de sete componentes (V4), pasta de staging independente (V5), arquivo separado de globals e um SHA-256 de referência. Ele valida a existência e hashes de **todos os sete componentes** e o conjunto de **seis componentes copiados ao laboratório**, garantindo que os hashes do banco original e do stage coincidam. Confere também o digest do arquivo externo de globals.

Ele **não executa o conteúdo do arquivo de globals**, não descifra, não roda SQL, não usa Docker, não envia dados pela rede e não registra paths, roles, SQL, tokens ou passwords. O cofre de secrets permanece separado.

O output obrigatório impede falsa certeza: `GLOBALS_SOURCE_PROVENANCE_ATTESTED=NO`, `GLOBALS_ROLE_SEMANTICS_AUDITED=NO` e `RECOVERY_READY=NO`. O arquivo SQL com SHA correto não prova que foi capturado do mesmo snapshot PostgreSQL original nem que sua execução seria segura. A integridade dos arquivos é distinta de sua proveniência e da capacidade de restaurar.

### Testes sintéticos

- Workflow integrado PG17 garante senha inválida/tag GCM adulterada bloqueados, owner/GRANT/DEFAULT ACL/RLS preservados e detecção de REVOKE.
- `.github/workflows/guardian-v59-disaster-evidence.yml` valida Windows e Linux com sete componentes sintéticos e pacotes incompletos: corrupção de globals, alteração de stage e ausência de secrets-vault devem impedir sucesso.

## O que falta para um Guardian operacional

1. Criar o Backup Geral **de verdade** (capturar código Web, API, Storage, DNS, configurações e banco com um identificador de release consistente), com cofre de secrets e cópia offsite.
2. Recuperar a referência oficial de globals/roles do banco autêntico e testar extensão/versões/ACLs em novo destino Supabase-comparável; não executar globals de fonte desconhecida.
3. Executar restore do backup verdadeiro em laboratório **seguro e previamente aprovado**, com relatório de dados e sem afetar os quatro containers originais.
4. Implantar front/API/Storage e validar login e corrida sintética, medir tempo total até HTTPS e então solicitar autorização de DNS/publicação.

**Meta do proprietário:** Criar Backup, Testar Recuperação, Recuperar Sistema; backup MANUAL antes de atualizações, meta total de recuperação RTO 4–6h ainda não comprovada.

Links operacionais: `docs/guardian-error-ledger-and-nonregression.md` e `docs/guardian-v58-encrypted-lab-restore-and-audit.md`.
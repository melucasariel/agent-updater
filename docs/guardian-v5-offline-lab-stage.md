# Radar Guardian V5 — laboratório de recuperação seguro e atômico

**Objetivo operacional:** recuperação do TaxiRadar em até **4–6 horas**, a comprovar em um ensaio integral. O usuário faz backups **manualmente**, sobretudo antes de publicar atualizações. **Nenhuma rotina de backup a cada quatro horas está autorizada.**

## Implementado neste major update

`scripts/GuardianV5-LabStage.mjs` recebe um conjunto privado dos sete componentes já existentes no formato de `docs/guardian-v4-coverage.md`. Revalida todos em memória e prepara seis componentes locais em uma pasta nova: banco `.r62db` ainda criptografado, Web, API, Storage, inventário DNS e configuração não secreta. **Não copia o cofre de secrets**, não descriptografa banco, não aplica SQL, não publica API/Web e não alcança serviços de produção.

O staging utiliza diretório temporário privado, compara SHA-256 da origem e do destino em cada cópia, repete a conferência antes de publicar a pasta e só então faz rename local. Falhas antes do rename limpam somente o diretório temporário criado pelo próprio processo. Diretórios existentes nunca são sobrescritos.

## Pré-requisito do laboratório

Crie um diretório NOVO e exclusivo para testes, fora das pastas dos sete componentes, contendo o arquivo exato `.rota62-guardian-lab-only`, com conteúdo `ROTA62_OFFLINE_LAB_V1` seguido de quebra de linha. Evite discos sincronizados ou pastas do site publicado. Não use como root o diretório original de backup, a raiz do disco ou uma pasta de produção.

Um exemplo PowerShell após instalação de Node e checkout local revisado:

~~~powershell
$lab=Join-Path $env:TEMP 'R62_GUARDIAN_LAB_V5'
New-Item -ItemType Directory -Force -Path $lab | Out-Null
[IO.File]::WriteAllText((Join-Path $lab '.rota62-guardian-lab-only'), "ROTA62_OFFLINE_LAB_V1`n",[Text.UTF8Encoding]::new($false))
node .\scripts\GuardianV5-LabStage.mjs --config C:\PRIVATE\guardian-input.json --lab-root $lab --mode plan
node .\scripts\GuardianV5-LabStage.mjs --config C:\PRIVATE\guardian-input.json --lab-root $lab --mode stage
~~~

O primeiro comando não grava arquivos, o segundo grava apenas dentro do laboratório marcado, criando `restore-<16-character-db-hash>` uma única vez. O relatório não contém caminhos nem nomes privados. O laboratório tem manifesto local com caminhos **relativos** e hashes para testes futuros. Não envie esse manifesto para um repositório público.

## Critérios de segurança e limites

- O `source gate` exige **7/7 componentes já presentes**; a operação prepara **6/7** e mantém o cofre separado. O módulo ainda não captura arquivos nem cria pacote geral criptografado.
- O arquivo `.r62db` continua criptografado e tem SHA-256 igual à referência do usuário, mas a origem da cópia não foi autenticada com certificado independente.
- Um site/API/configuração local copiado pode ainda conter endpoints de produção; **não executar arquivos da pasta preparada** sem isolamento de rede efetivo e mocks. Esse módulo apenas copia bytes e não inicia servidores.
- `manifest.json` é inventário local para validação de cópia, **não é assinado**. Não comprova que os seis artefatos são consistentes temporalmente.
- Os testes CI Linux e Windows são **sintéticos**, sem dados, senhas ou serviços reais, e não demonstram recuperação ponta a ponta.
- A pasta de staging é criada no mesmo sistema de arquivos para permitir rename atômico. O projeto evita sobrescrever/restaurar conteúdo em diretórios já existentes; não há limpeza ou remoção dos backups originais.

**Próximo major release:** adaptar restaurador real a um destino descartável: reconstituir roles, schema/data e ACLs do `.r62db` via fluxo aprovado, configurar Web/API e Storage sem conectar à produção, executar smoke tests fictícios e medir RTO real. Mudanças de DNS e publicação exigem confirmação humana separada.
## Independent offline stage verification

After staging, verify the folder again **without the original backup sources**:

~~~powershell
node .\scripts\GuardianV5-VerifyStage.mjs --stage (Join-Path $lab 'restore-<16-character-db-hash>')
~~~

The verifier checks all six staged roles, every listed SHA-256, file lengths, missing files, extra files and traversal or symlink attempts. It never needs credentials, a live Supabase project or access to the original source directory. A modified `manifest.json` can be forged by anyone with write access to the lab; independent authenticated manifest signing and secure offsite copies are still necessary.

**Important:** Offline staging is preparation, not a functional database restore. The `.r62db` remains encrypted and no API/website is started.

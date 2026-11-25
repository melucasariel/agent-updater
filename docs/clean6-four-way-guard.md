# CLEAN6 Four-Way Guard V1 — integração local segura

O comando scripts/Audit-Clean6FourWay.mjs compara, em uma única execução, os catálogos PostgreSQL 17 dos quatro containers já identificados. Usa a exportação SQL do repositório em transação READ ONLY e duas leituras independentes por container, com rejeição se os fingerprints divergirem. O comparador usa identidade de objeto separada do proprietário e chaves de ACL sem descartar duplicações.

Para executar em um checkout local revisado, com Node e Docker funcionando, no PowerShell:
node .\scripts\Audit-Clean6FourWay.mjs --containers 4645575c1617,9576b226ca0a,44fc8a2a3995,529fc3927b48 --reference 44fc8a2a3995

Controle de segurança: somente imagem com postgres, container em execução, um volume Docker sem bind mount, uma rede Docker marcada internal, nenhuma porta publicada e um banco PG17 com 76 tabelas e 6 extensões adicionais (sem plpgsql). O script consulta catálogos via socket local de dentro do container; não solicita senhas nem acessa linhas de passageiros. Em caso de falha, bloqueia o respectivo container. Não garante que outros containers na mesma rede não tenham egress nem comprova a origem do backup.

Não baixa código remoto automaticamente, não registra inventários em disco, não imprime nomes dos objetos nem usuários, não altera SQL, Docker ou backup. Produz contagens, hashes compactos e diferenças por proprietário e ACL. **A referência indicada é provisória.**

A contagem histórica 185 owners/595 ACLs é de outro escopo, e não pode ser confrontada diretamente com os 1909 registros observados anteriormente. O resultado da auditoria não comprova integridade ou proveniência do arquivo .r62db. O teste real do backup exigirá um inventário independente obtido do artefato criptografado em ambiente isolado e validação da origem dos dados. Não publicar backups, manifests privados ou relatórios com informações sensíveis no repositório público.

Protocolo CI: regressões sintéticas de comparação no Windows e execução com PostgreSQL 17 real em rede Docker internal e volume descartáveis no Linux. A execução local depende de instalação/checkout e autorização do operador; o GitHub não executa automaticamente no computador do usuário.

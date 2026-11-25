# ROTA62 Guardian — canal de atualizações

Repositório público dedicado **somente à distribuição de atualizações do Guardian Agent**.

**Não incluir aqui** backups de banco, arquivos `.r62db`, tokens de sessão, secrets Supabase, chaves privadas, credenciais, dados de passageiros ou motoristas, arquivos DPAPI ou dumps de diagnóstico.

## Estado atual

- Agent local relatado: v3.0.
- Atualizações remotas: **desativadas** até que a chave pública de verificação esteja configurada e testada.
- Nenhum pacote executável está aprovado para instalação neste repositório.
- O projeto TaxiRadar de produção não deve ser modificado por este canal.

## Modelo de lançamento

1. Criar pacote reproduzível, sem informações sensíveis.
2. Calcular SHA-256 dos bytes exatos do pacote.
3. Gerar manifesto com versão, hash, URL HTTPS e versão mínima do Agent.
4. **Assinar o manifesto com chave privada mantida fora deste repositório**, preferencialmente em ambiente de publicação isolado.
5. Publicar manifesto, assinatura e pacote como assets de uma GitHub Release imutável.
6. O Agent valida assinatura usando chave pública previamente fixada, confere o SHA-256, compatibilidade, versão e URL autorizada.
7. Instala com backup e recuperação automática em caso de falha; nunca executa conteúdo vindo de clipboard sem autorização explícita.

## Política de segurança

- Nunca aceitar manifesto não assinado, chave pública recuperada da mesma atualização sem confiança prévia, ou atualização que reduza versão sem autorização.
- Não usar `Invoke-Expression` nem executar scripts de URLs não validadas.
- Diagnósticos somente leitura podem ser automatizados; qualquer alteração em PostgreSQL, Docker, rede ou restauração exige autorização separada.
- Tags ou Releases não substituem verificação criptográfica.
- Não publicar nenhuma Release de produção até o ciclo completo de assinatura, download, validação e rollback passar em laboratório.

Veja `docs/update-policy.md` para requisitos adicionais.

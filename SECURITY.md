# Política de Segurança do CCcam3

## Reportar Vulnerabilidades

Se encontrares uma vulnerabilidade de segurança, **não abras uma issue pública**.

Envia um email com os detalhes (passos para reproduzir, impacto, versão afetada)
para o maintainer. A resposta é dada, em princípio, dentro de 7 dias:

- Confirmação da receção
- Análise e correção
- Publicação de um aviso e da correção após a release

## Versões Suportadas

| Versão | Suporte |
|---|---|
| 3.0.x (mais recente) | ✅ Correções de segurança |
| Versões anteriores | ❌ Atualizar para a mais recente |

## Notas de Segurança Conhecidas

- A API REST usa HTTP Basic **em claro** — para exposição à internet usar
  sempre um proxy HTTPS à frente da API.
- Passwords e chaves ficam em texto simples nos ficheiros de configuração
  (`cccam3.users`, `SoftCam.Key`) — manter permissões `0600` (o servidor
  aplica-as ao gravar) e não partilhar os ficheiros.
- Binários estáticos não fazem resolução de hostnames em algumas boxes —
  nos readers remotos usar sempre **IP**.
- Os modos RC4/AES-CBC/3DES-CBC são legado sem autenticação; o modo
  recomendado é **AES-GCM** (por omissão desde a 3.0.2).

## Boas Práticas de Operação

1. Mudar sempre as passwords por omissão (`admin/admin123`)
2. Limitar o acesso à API REST com `[rest_api] user/password`
3. Usar os filtros de IP (`allow_ips`/`deny_ips`) quando possível
4. Manter o sistema e o OpenSSL atualizados

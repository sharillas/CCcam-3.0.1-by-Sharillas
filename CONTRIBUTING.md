# Contribuir para o CCcam3

Obrigado pelo interesse em contribuir! O projeto é GPLv3 e as
contribuições são bem-vindas.

## Regras de Ouro

1. **Uma mudança por commit** — commits pequenos e descritivos
2. **Correções com testes** — se corrigires um bug, acrescenta um teste
3. **Sem quebrar a CI** — `make test` tem de passar
4. **Licença** — o teu código fica sob GPLv3; código portado de outros
   projetos GPL (ex.: OSCam) tem de manter a atribuição no cabeçalho

## Fluxo de Trabalho

```bash
# 1. Fork + clone
git clone https://github.com/<o-teu-user>/CCcam-3.0.1-by-Sharillas.git
cd CCcam-3.0.1-by-Sharillas

# 2. Branch para a funcionalidade
git checkout -b feature/nova-func

# 3. Desenvolver e testar localmente
make clean
make
make test

# 4. Commit + push + PR
git commit -m 'Adiciona nova funcionalidade'
git push origin feature/nova-func
```

## Estrutura do Código

| Pasta | Responsabilidade |
|---|---|
| `src/core/` | Servidor, config, pool de clientes, logger |
| `src/network/` | Protocolo, handshake, criptografia, Newcamd, compat CCcam real |
| `src/CCshare/` | Cache, ECM, leitores, hops, utilizadores, EMU |
| `src/hardware/` | DVB direto, DVBAPI, STAPI, smartcard (PC/SC) |
| `src/api/` | API REST + painel web |

Ver `docs/HISTORICO.md` para o histórico completo e as decisões técnicas.

## Convenções

- C99, comentários em português, indentação de 4 espaços
- Logs via `cccam_log(LOG_DEBUG/INFO/WARN/ERROR, ...)`
- Estruturas partilhadas entre threads: atómicos ou mutexes próprios
  (ver o padrão usado na cache e no user manager)
- Parsers de rede: bounds checks SEMPRE (a entrada é adversária)

## Testes

```bash
make test          # self-tests integrados (./bin/cccam3 -t)
```

A CI corre também sanitizers (ASan/UBSan), build `-Werror` e fuzzing do
parser — os jobs estão em `.github/workflows/ci.yml`.

## Issues

- Reporta bugs com: versão, arquitetura, config relevante e logs
- Para vulnerabilidades de segurança, ver `SECURITY.md` (não usar issues públicas)

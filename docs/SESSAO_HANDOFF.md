# Handoff de Sessão — CCcam3 (ponto de partida para a próxima sessão)

> Este ficheiro resume o estado do projeto para uma nova sessão continuar
> sem repetir trabalho. Ver `docs/HISTORICO.md` para o histórico completo.

## Estado atual (data: 2026-09-15)

- **Versão**: 3.0.2 (`include/cccam3.h` → `CCCAM3_VERSION`)
- **Repo**: https://github.com/sharillas/CCcam-3.0.1-by-Sharillas (branch `main`, privada/colaborativa)
- **Último commit**: `2ffde9d` — README com capturas de ecrã
- **CI**: 5 jobs verdes em cada push (`build-test` com smoke, `sanitize` ASan/UBSan,
  `werror` -Werror, `fuzz` libFuzzer, `warnings-report`)
- **Release**: v3.0.2 publicada — 6 binários estáticos (x86_32/64, armv7, aarch64,
  mipsel, mips64el) + `enigma2-plugin-softcams-cccam3_3.0.2_all.ipk`
  (o workflow `build-release.yml` cria a release automaticamente no push de um tag `v*`)
- **Feed opkg**: live em https://sharillas.github.io/CCcam-3.0.1-by-Sharillas/
  (branch `gh-pages`, gerado por `tools/make_opkg_feed.sh`)

## Implementado (compacto)

1. **Fundações**: 6 headers em falta, includes, Makefile; servidor ligado
   end-to-end (login → handshake → ECM → cache → leitor → CW)
2. **Segurança**: framing de 12 bytes endian-safe, AES-GCM por omissão
   (incl. handshake legado com chave SHA256), AES/3DES-CBC com IV por mensagem,
   RC4 com keystream contínua, SHA256 nas passwords, RAND_bytes, fchmod 0600
3. **Concorrência**: thread por cliente, refcount no pool de clientes,
   mutexes (users com reload copy-swap, cache rwlock LRU), REST thread-pool limitada
4. **Módulos reais**: Newcamd (DES + MD5-crypt), DVBAPI ca_pmt, DVB direto
   S/S2/C/C2 (com zapping `/dvb/zap` e autoscan de adaptadores), EMU
   (Viaccess/BISS/Cryptoworks/PowerVU/Nagra2/Irdeto2 + EMM AU), smartcard PC/SC, STAPI
5. **CCcam comercial**: Fase 1 (clássico 2.0.11–2.1.4) + Fase 2 (modo estendido
   `[EXT]` para 2.2.x–2.3.0) em `src/network/cccam3_cc_legacy.c` (portado do OSCam, GPLv3)
6. **REST**: auth Basic, `/status /stats* /clients /users /readers /files*
   /reload/* /emu/keys /channels /healthz /metrics (Prometheus) /dvb/zap`
7. **Distribuição**: `install.sh` (curl→wget→python, deteta opkg→IPK),
   pacote IPK com plugin de menu enigma2, wrapper `cccam3 start|stop|...`
8. **Docs**: HISTORICO (§1–24), INSTALL, API, README com screenshots,
   SECURITY/CHANGELOG/CONTRIBUTING, `configs/` e `examples/` comentados

## Pendências (ordem sugerida)

| # | Item | Notas |
|---|---|---|
| 1 | **Testes com clientes CCcam reais** (2.0.11/2.1.4/2.2.x) e boxes físicas | crítico; a Fase 1/2 foi portada da especificação OSCam e precisa de validação real |
| 2 | Substituir as screenshots do README por capturas reais de produção | mesmos nomes em `docs/screenshots/` |
| 3 | CCcam Fase 3 (ChaCha 2.3.2+) | opcional — clientes caem no clássico sem anúncio de chaCha |
| 4 | Multi-tuner DVB | requer refatorar `dvb.c` para instâncias |
| 5 | Rever `-Wno-*` dos módulos EMU (relatório em CI `warnings-report`) | array-bounds/stringop-overflow restantes |
| 6 | **Rotar o token GitHub partilhado no chat** | foi usado nos pushes |

## Como retomar

```bash
git clone https://github.com/sharillas/CCcam-3.0.1-by-Sharillas.git
cd CCcam-3.0.1-by-Sharillas
make clean && make && make test          # compila + self-tests
./bin/cccam3 -c conf/cccam3.conf         # corre o servidor
```

- CI corre em cada push (5 jobs); releases: `git tag -a v3.0.3 -m ... && git push origin v3.0.3`
- Ficheiros chave: `src/core/cccam3_server.c` (threads/loop), `src/network/cccam3_cc_legacy.c`
  (compat CCcam), `src/api/cccam3_rest_api.c`, `src/hardware/cccam3_dvb.c`
- Para alterações na repo é preciso um token GitHub válido (o anterior foi partilhado no chat)

# CCcam3 - Histórico Completo do Desenvolvimento

Este documento descreve tudo o que foi feito e implementado neste projeto desde a análise inicial do repositório original, para que possa ser analisado e compreendido em qualquer outro computador.

---

## 1. Visão Geral

O projeto é uma reimplementação de um servidor de cardsharing baseado no conceito do protocolo CCcam, escrita em C para Linux, com:

- Servidor multi-cliente (protocolo próprio tipo CCcam)
- Servidor Newcamd integrado
- Leitores remotos reais (cliente TCP que pede CWs a outros servidores)
- Leitor direto do tuner DVB (S/S2/C/C2) via `/dev/dvb` — obtém a info do canal e vai buscar as CWs aos leitores remotos
- API REST + interface web
- Configuração completa por ficheiro `.conf`
- Compilação automática multi-arquitetura via GitHub Actions (x86 32/64, ARMv7, ARM64, MIPS32, MIPS64)

**Fluxo principal**: cliente liga → login com autenticação → handshake (deriva chave de sessão) → envia ECMs → o servidor verifica a cache de CWs, senão pede ao leitor (local/remoto/EMU) → devolve a CW ao cliente. O leitor DVB local faz o mesmo papel de cliente: lê ECMs do tuner e injeta as CWs recebidas no descrambler.

---

## 2. Estado Original da Repo (antes do trabalho)

O repositório original tinha 21 ficheiros `.c` e 8 headers, mas **não compilava** e **nada estava ligado entre si**:

### 2.1 O código não compilava
| Problema | Detalhe |
|---|---|
| 6 headers usados não existiam | `cccam3_logger.h`, `cccam3_protocol.h`, `cccam3_client.h`, `cccam3_utils.h`, `cccam3_crypto.h`, `cccam3_stapi.h` eram incluídos por dezenas de `.c` mas nunca foram criados |
| Include paths errados | `include/cccam3.h` inclui headers que vivem em `src/core`, `src/network`, `src/CCshare`, `src/api`, `src/hardware`, mas o Makefile só tinha `-Iinclude` |
| Faltavam includes de sistema | `openssl/sha.h` (utils.c), `stdlib.h` (handshake_advanced.c), `stdio.h` (ecm/cache/optimizer), `unistd.h` (web_interface.c), `arpa/inet.h` (utils.c) |
| Constante mal escrita | código usava `CCCAM_HEADER_SIZE` mas o header define `CCCAM3_HEADER_SIZE` |
| Estrutura incompleta | `cccam_hop_entry_t` não tinha o campo `next` usado em todo o `hop_control.c` |
| `cccamm3_client.c` não incluía `cccam3_client.h` (onde está `CCCAM3_CLIENT_SLOTS`) |

### 2.2 Nada estava ligado entre si
- O loop do servidor (`cccam3_run`) aceitava clientes e **abandonava-os**: o fd aceite nunca era lido nem fechado (leak). `cccam_client_create`, o handshake e o processamento de ECMs nunca eram chamados pela rede
- A criptografia era definida mas nunca usada (`cccam_protocol_set_crypto` nunca chamado; `g_crypt_mode` ficava sempre `NONE`)
- A configuração era lida e ignorada: as secções `[rest_api]`, `[newcamd]`, `[web_interface]`, `[user_manager]`, `[dvbapi]`, `[stapi]`, `[security]` tinham parsing vazio
- As chaves do `.conf` não batiam com o parser (`[logging] level` vs `log_level`, etc.)
- `make test` corria `./cccam3 -t` mas a opção `-t` não existia
- CWs dos leitores eram simuladas (hardcoded)

### 2.3 Bugs de memória/lógica
- Header do protocolo inconsistente: `CCCAM3_HEADER_SIZE` era 8 mas o header escrito/lido tinha 12 bytes (overflow de 4 bytes + framing desalinhado)
- Overflow no handshake RSA: escrevia 60 bytes num buffer de 16
- `cccam_handshake_encrypt` em AES-GCM escrevia `len+28` bytes num buffer de `len`
- UB: `snprintf(buf, size, "%s", buf)` (mesmo buffer origem/destino) na REST API
- JSON inválido em `/stats` (removia o `{` mas deixava o `}`)
- Página web truncada (HTML ~8.8KB num buffer de 8KB)
- Hop control bloqueava o 2º ECM do mesmo cliente/canal ("LOOP DETECTADO" falso) — nenhum cliente real conseguia ver um canal
- Casts unaligned `*(uint32_t *)ptr` — crash em MIPS/ARM antigos
- Seeds com `rand()` e hash de passwords FNV repetido 4x (sem SHA256)

---

## 3. Ponto 1 — Fazer o Projeto Compilar

### 3.1 Headers criados
| Ficheiro | Conteúdo |
|---|---|
| `src/core/cccam3_logger.h` | Níveis de log + `cccam_log/init/close` |
| `src/core/cccam3_client.h` | API de gestão de clientes + `CCCAM3_CLIENT_SLOTS` |
| `src/core/cccam3_utils.h` | Endianness, seed, SHA1, hash FNV |
| `src/network/cccam3_protocol.h` | Parse/build de mensagens, criptografia, handshake |
| `src/network/cccam3_crypto.h` | RC4 / AES / 3DES |
| `src/hardware/cccam3_stapi.h` | Stub STAPI |

### 3.2 Correções
- `Makefile`: `-Isrc/core -Isrc/network -Isrc/CCshare -Isrc/api -Isrc/hardware`
- `build_release.sh` / `build_cccam3_release.sh`: os CFLAGS sobrescritos nesses scripts também receberam os novos `-I`; caminho `scripts/build_release.sh` corrigido para `build_release.sh` (igual no `build_cccam3_upload.sh`)
- Includes de sistema em falta adicionados aos 7 `.c` afetados

---

## 4. Ponto 2 — Ligar o Fluxo do Servidor

### 4.1 O que foi ligado
- Loop `select()` monitoriza agora o socket de escuta + todos os sockets de clientes (novo `cccam_client_get_by_index`)
- `accept` → `cccam_client_create` + balanceador de ligações (`cccam_load_balancer_*`, respeita `max_clients`)
- Leitura completa de mensagens por socket (`recv_exact` + `read_client_message`, com `SO_RCVTIMEO` de 10s anti-stall)
- `CCCAM_MSG_LOGIN` → parse do payload (handshake+user+pass+versão, com `strnlen` e bounds) → `cccam_user_manager_authenticate` → `cccam_protocol_handle_login` (handshake) → define criptografia → envia `LOGIN_ACK` com a resposta do handshake → cliente autenticado
- `CCCAM_MSG_ECM` → parse → `cccam_ecm_process` (hop check → cache → leitor) → `cccam_ecm_send_cw` + estatísticas por utilizador
- `CCCAM_MSG_KEEPALIVE` → atualiza `last_keepalive`; timeouts de 120s; `SIGPIPE` ignorado; `cccam_client_close_all()` no shutdown

### 4.2 Dependências criadas para ligar o fluxo
- `cccam_protocol_build_login_ack` (não existia)
- `cccam_handshake_get_response_len` + `cccam_handshake_get_session_key` — a chave de sessão derivada no handshake estava presa dentro do módulo
- `CCCAM3_HEADER_SIZE` corrigido de 8 → 12 (framing do ponto 3 veio por dependência)
- Hop control: removido o falso "LOOP DETECTADO" que bloqueava pedidos repetidos legítimos

### 4.3 Fluxo de mensagens
```
cliente ──login──▶ servidor
  payload: handshake[16] + user\0 + pass\0 + versão(4)
servidor ──auth──▶ user_manager (SHA256)
servidor ──handshake──▶ deriva chave de sessão (PBKDF2 p/ RSA-AES | SHA1 p/ legado)
servidor ──LOGIN_ACK──▶ cliente (seed/IV/cipher/tag, 16 ou 60 bytes conforme modo)
cliente ──ECM──▶ servidor
  payload: caid(2) provid(2) sid(2) + ecm_data
servidor ──hop check──▶ cache? ──hit──▶ CW imediata
                          └miss──▶ card_manager ──▶ leitor (local/remoto/EMU)
servidor ──CW──▶ cliente
  payload: ecm_time(4) cw(16) hop(1) caid(2) provid(2) sid(2)
```

---

## 5. Ponto 3 — Correções de Segurança/Framing

- `protocol.c` reescrito com helpers `read_be32/write_be32/read_be16/write_be16` via `memcpy` (fim dos casts unaligned — seguro em MIPS/ARM), validação explícita de `msg_len`, bounds em todos os builders
- `protocol_newcamd.c`: mesmo tratamento
- Handshake: `cccam_handshake_encrypt(data, len, capacity)` — fim do overflow de +28 bytes; `rsa_server/legacy_server` recebem o tamanho do buffer de resposta; AES exige múltiplos de 16
- `rest_api.c`: fim do UB `snprintf` sobreposto — JSON e HTTP em buffers separados com `Content-Length`; `/stats` produz JSON válido; rota `/channels`
- `web_interface.c`: buffer dinâmico (página completa)
- `utils.c`: seeds com `RAND_bytes` (fallback rand apenas se falhar)
- `user_manager.c`: passwords com SHA256 hex (fim do FNV fake)

---

## 6. Configuração Completa

`cccam_config_t` estendido com campos para todas as secções; o parser (`cccam3_config.c`) trata:

| Secção | Chaves | Aplicado a |
|---|---|---|
| `[global]` | port, server_name, max_clients | socket de escuta |
| `[logging]` | level, file, enabled | logger |
| `[cache]` | enabled, timeout | `cccam_cache_set_enabled/timeout` |
| `[security]` | allowed_crypt_modes (bitmask: 0x01 RC4, 0x02 AES, 0x04 3DES, 0x10 AES-GCM) | `cccam_protocol_set_allowed_modes` |
| `[hop_control]` | max_hops, timeout | `cccam_hop_control_set_limit/timeout` |
| `[rest_api]` | port, enabled | inicia/desativa a API REST |
| `[web_interface]` | enabled | — |
| `[user_manager]` | enabled, file | ficheiro de users (fallback `/etc/cccam3/`) |
| `[newcamd]` | enabled, port | listener Newcamd |
| `[dvbapi]` | enabled, socket | socket OSCam-style |
| `[dvb]` | enabled, adapter, frontend, demux, frequency_khz, symbol_rate, delivery_system, modulation, fec, inversion, polarity, service_id | leitor DVB direto |
| `[stapi]` | enabled, device | stub STAPI |

Nota: os nomes legados (`cache_enabled`, `log_level`, ...) continuam a funcionar.

---

## 7. Servidor Newcamd

- Listener na porta configurada, integrado no mesmo loop `select()` (single-thread, sem races com cache/card manager)
- `NEWCAMD_CMD_LOGIN` (payload `user\0pass\0`) → autenticação via user manager → ACK "OK"
- `NEWCAMD_CMD_ECM` → mesmo processamento → CW devolvida em framing Newcamd
- Framing: cmd(4) + len(4) + payload

---

## 8. Leitores Remotos Reais

`card_manager.c`:
- `remote_connect`: socket TCP real (fim da ligação "simulada"), `SO_RCVTIMEO` 10s
- `remote_get_cw`: login CCcam (`cccam_protocol_build_login`, versão 301 → RSA), lê o ACK, envia ECM (`cccam_protocol_build_ecm`), lê a CW (`remote_read_message`), extrai cw+hop
- Em falha: fecha o socket e religa no próximo pedido
- Seleção de leitor por score (prioridade, hop, tipo, estado) em `cccam_card_manager_select_reader`
- Leitores locais (smartcard) e EMU continuam simulados — **sem leitura direta de cartões**, conforme pedido

---

## 9. Leitor DVB Direto (S/S2/C/C2)

Novo módulo `src/hardware/cccam3_dvb.c`:

1. Abre `/dev/dvb/adapterN/frontendM` (+ 2 demux: um para secções, um para PES/descrambler)
2. Sintonia via `FE_SET_PROPERTY`: delivery system (auto-detetado pelo tipo do frontend se não definido), frequência, symbol rate, inversão, modulação (QPSK/PSK-8/QAM-16..256), FEC, voltagem LNB por polaridade (S/S2); aguarda `FE_HAS_LOCK`
3. **Info do canal**: PAT (pid 0x0000) → lista de serviços; SDT (pid 0x0011, tabela 0x42) → nomes; PMT de cada serviço → CAID + ECM PID (descritor CA 0x09) + vídeo PID
4. Seleção de serviço: `service_id` da config ou o primeiro com ECM
5. Captura de ECMs: filtro de secção no demux (tabela 0x80/0x81, máscara 0xF0 — par/ímpar)
6. `cccam_ecm_process` → cache/leitores remotos → CW
7. Injeção da CW: `DMX_SET_DESCRAMBLER` (index par/ímpar, flags ODD/EVEN) no demux do vídeo + filtro PES no vídeo PID
8. Ressintoniza em caso de perda de sinal

Compatibilidade: `DMX_SET_DESCRAMBLER` não existe no kernel mainline — o módulo define a estrutura/ioctl localmente (`_IOW('o', 47, ...)`), compatível com kernels de STBs (Dreambox/VU+); se o kernel não suportar, regista em log e continua (as CWs continuam a ser obtidas).

---

## 10. API REST

Endpoints (porta por omissão 8080):

| Rota | Resposta |
|---|---|
| `/` e `/status` | estado do servidor (porta, clientes, hop limit, rest_port, versão) |
| `/stats` e `/stats/all` | tudo (server + cache + ecm + readers) |
| `/stats/cache` | entradas, hits, misses, hit_ratio |
| `/stats/ecm` | total, cache hits/misses, reader success/fail |
| `/stats/readers` | total/ativos/locais/remotos |
| `/channels` | lista de serviços do transponder DVB (SID, CAID, ECM PID, nome) |
| `/web` | painel web (HTML) |

---

## 11. Testes

`make test` corre `./bin/cccam3 -t` (self-tests): cache add/find, round-trip build/parse de login, autenticação de utilizador, hop control.

---

## 12. CI e Releases

`.github/workflows/build-release.yml`:
- Triggers: `workflow_dispatch` (manual) e `release: published`
- Matrix de 6 arquiteturas: x86_32, x86_64, armv7, aarch64, mipsel, mips64el
- Compila OpenSSL 1.1.1w estático por arquitetura (cache), depois o CCcam3 com `-Wl,-Bstatic -lssl -lcrypto -Wl,-Bdynamic`
- Faz upload do binário para a release (tag configurável)

Release v3.0.1: binários das 6 arquiteturas + pacotes de código-fonte.

### 12.1 Compatibilidade por Arquitetura

| Asset (binário) | Descrição | Boxes / Servidores compatíveis |
|---|---|---|
| `cccam3-x86_64` | Linux 64 bits | VPS e servidores dedicados (Ubuntu, Debian, CentOS/Rocky, Fedora...), PCs, NAS x86_64 (Synology/QNAP x86) |
| `cccam3-x86_32` | Linux 32 bits | VPS/servidores 32 bits antigos, PCs antigos com distros i386 |
| `cccam3-armv7` | ARM 32 bits (ARMv7 hard-float) | Raspberry Pi 2/3 (e Pi 4 em modo 32 bits), boxes DVB ARM 32 bits (Dreambox One/Two, Amiko, Mutant, Edision, AX/Mutant HD51...), TV boxes Android/Linux ARMv7 |
| `cccam3-aarch64` | ARM 64 bits | Raspberry Pi 4/5 (64 bits), boxes DVB ARM64, servidores ARM64 (AWS Graviton, Oracle Cloud Ampere), NAS ARM64 |
| `cccam3-mipsel` | MIPS 32 bits little-endian | Boxes DVB MIPS clássicas: Vu+ Duo/Solo/Solo2/Ultimo, Dreambox DM500HD/DM7020HD/DM8000, Gigablue, Zgemma (série H MIPS), Octagon MIPS |
| `cccam3-mips64el` | MIPS 64 bits little-endian | Boxes DVB com CPUs MIPS64 (menos comuns; usar este em boxes MIPS64) |

> Nota: nas boxes DVB (mipsel/armv7) o descrambler funciona se o kernel tiver o patch de descrambling do demux; senão, usa-se o CCcam3 apenas como servidor de share.

---

## 13. Bugs Reais Apanhados pela Compilação (CI)

1. `CCCAM_HEADER_SIZE` vs `CCCAM3_HEADER_SIZE` (protocol.c, server.c, card_manager.c)
2. `CCCAM3_CLIENT_SLOTS` sem o include de `cccam3_client.h`
3. `cccam_hop_entry_t` sem o campo `next`
4. Workflow não passava o compilador cross (`CC`) ao OpenSSL
5. URL do tarball do OpenSSL (espelho GitHub em vez de openssl.org)

---

## 14. Limitações Conhecidas

- Criptografia é estado global por servidor (modo/chave partilhados entre clientes) — per-client ficou para futuro
- Leitores locais (smartcard) e EMU continuam simulados (dependem de hardware/algoritmos CA reais)
- O wire format é próprio — clientes CCcam comerciais reais continuam incompatíveis, apesar do que o README original prometia
- Compatibilidade Newcamd usa o framing próprio do projeto (sem encriptação DES do newcamd real)
- `DMX_SET_DESCRAMBLER` requer kernel de STB com o patch de descrambling

---

## 15. Estrutura de Ficheiros

```
.
+-- Makefile                     # build (6 dirs de include)
+-- install.sh                   # instalador de 1 comando (VPS/box)
+-- build_release.sh             # build multi-arch local (requer cross-gcc)
+-- build_cccam3_release.sh      # clone+update+build numa só máquina
+-- build_cccam3_upload.sh       # envia para VPS por scp e compila lá
+-- .github/workflows/build-release.yml   # CI de binários multi-arch
+-- README.md                    # visão geral + instalação
+-- conf/
|   +-- cccam3.conf              # todas as secções documentadas
|   +-- cccam3.users             # utilizadores (hash SHA256 ao carregar)
|   +-- cccam3.readers           # leitores local/remoto/emu
+-- examples/
|   +-- cccam3.conf              # TODAS as opções comentadas em detalhe
|   +-- cccam3.users             # exemplo comentado (níveis, max_hops...)
|   +-- cccam3.readers           # exemplo comentado (local/remoto/emu)
|   +-- cccam3.service           # unidade systemd de exemplo
|   +-- README.md                # índice + opções da linha de comandos
+-- include/
|   +-- cccam3.h                 # constantes, IDs de mensagens, modos crypto
|   +-- cccam3_structs.h         # todas as estruturas + cccam_config_t
+-- src/core/
|   +-- cccam3_server.c          # main, init, loop, login/ECM/newcamd, self-tests
|   +-- cccam3_config.c          # parser completo do .conf
|   +-- cccam3_client.c          # pool de clientes
|   +-- cccam3_logger.c          # log stdout+ficheiro com níveis
|   +-- cccam3_utils.c           # endianness, RAND_bytes, SHA1
|   +-- cccam3_optimizer.c       # memória/timeouts/load balancer/failover
+-- src/network/
|   +-- cccam3_protocol.c        # framing 12 bytes, parse/build, crypto modes
|   +-- cccam3_handshake.c       # handle_login (escolhe RSA_AES ou legado)
|   +-- cccam3_handshake_advanced.c  # RSA/AES-GCM/legado, chave de sessão
|   +-- cccam3_crypto.c          # RC4/AES/3DES (OpenSSL)
|   +-- cccam3_crypto_advanced.c # AES-GCM, RSA, PBKDF2 (OpenSSL EVP)
|   +-- cccam3_protocol_newcamd.c# framing Newcamd + login
+-- src/CCshare/
|   +-- cccam3_cache.c           # cache de CWs (lista LRU, enable/timeout)
|   +-- cccam3_ecm.c             # processo ECM: hop→cache→leitor→CW
|   +-- cccam3_card_manager.c    # leitores; REMOTO real via TCP
|   +-- cccam3_hop_control.c     # limite de hops configurável
|   +-- cccam3_user_manager.c    # users SHA256, níveis, ficheiro de users
+-- src/hardware/
|   +-- cccam3_dvb.c             # NOVO: tuner S/S2/C/C2 + ECMs + descrambler
|   +-- cccam3_dvbapi.c          # socket OSCam-style (clientes descodificadores)
|   +-- cccam3_stapi.c           # stub STAPI
+-- src/api/
|   +-- cccam3_rest_api.c        # HTTP/JSON + /channels
|   +-- cccam3_web_interface.c   # painel HTML
+-- docs/
|   +-- HISTORICO.md             # este ficheiro
|   +-- INSTALL.md / API.md
```

---

## 16. Instalação Rápida (VPS ou Box)

Um comando:

```bash
curl -fsSL https://raw.githubusercontent.com/sharillas/CCcam-3.0.1-by-Sharillas/main/install.sh | bash
```

O instalador deteta a arquitetura, descarrega o binário correto da release, instala as configurações em `/etc/cccam3/`, desativa o DVB automaticamente se não houver `/dev/dvb`, e instala o serviço (systemd ou init.d). Depois basta:

```bash
cccam3 -c /etc/cccam3/cccam3.conf        # manual
# ou, se o serviço foi instalado:
systemctl status cccam3
```

Compilação manual (para desenvolvimento):

```bash
make clean
make
make test
./bin/cccam3 -c conf/cccam3.conf
```

---

## 17. Produção Real — Correções de Bugs e Implementações Reais (2026)

Esta secção documenta a segunda ronda de trabalho: correção dos bugs críticos
e substituição de todas as funcionalidades simuladas por implementações reais.

### 17.1 Bugs críticos corrigidos

| # | Bug | Correção |
|---|---|---|
| 1 | Chave de sessão era estado global partilhado entre clientes | Novo `cccam_crypto_ctx_t` por sessão: cada cliente/leitor remoto tem a sua chave e modo. `cccam_protocol_*` passou a receber o contexto. |
| 2 | AES-GCM negociado mas tráfego em claro; `AES_set_encrypt_key` usado para desencriptar; AES/3DES sem validação de blocos (OOB) | AES-GCM real no protocolo (nonce = msg_id + contador, AAD = msg_id, tag 16B anexado ao payload); `AES_set_decrypt_key` na desencriptação; validação `len % 16` (AES) e `len % 8` (3DES). |
| 3 | `password_hash` escrevia 65 bytes num buffer de 64 | Campo `password_hash[65]` e escrita com bounds. |
| 4 | Leitores remotos ficavam excluídos para sempre após 1 falha | Estado OK reposto no sucesso; após 3 falhas consecutivas, backoff de 30 s (`retry_after`), voltando a tentar. |
| 5 | `connect` remoto bloqueante (podia travar o servidor) | Connect não bloqueante com timeout de 5 s (`poll`) + `SO_SNDTIMEO`/`SO_RCVTIMEO`. |
| 6 | `cache_timeout` da config ignorado; "LRU" era FIFO | `cccam_cache_add(..., expires_at=0)` usa o timeout configurado; lista duplamente ligada com promoção ao topo no hit e evicção da cauda (LRU verdadeiro). |
| 7 | Hop control ineficaz (clientes entravam no hop máximo) | O hop servido = hop da origem + 1; verificado contra o limite global e o limite do utilizador; cache guarda o hop da origem. |
| 8 | Logger reutilizava `va_list` sem `va_copy` (UB) | `va_copy` + bounds no nível + `localtime_r`. |
| 9 | REST API sem autenticação, parsing frágil, write parcial, race no cleanup | HTTP Basic (hash SHA256 em comparação), parsing de pedido/headers robusto, `send_all`, mutex+condvar para o arranque da thread. |

### 17.2 Implementações reais (fim das simulações)

- **EMU real (SoftCam.Key)**: parser de chaves F/I/T + motor Viaccess completo
  (Via 1, 2.6 e 3, incluindo HD sur-encryption D2 0F/11 e 13/15, portado do
  OSCam-emu) e BISS (mode 1 por SID/"All Feeds"). Ficheiro em `[emu] key_file`.
- **Leitor local real via PC/SC**: `cccam3_smartcard.c` fala com smartcards
  reais (Seca/Mediaguard via C1 3C/C1 3A, Conax via DD A2/DD CA, conforme o
  OSCam). Compilar com `make USE_PCSC=1` (libpcsclite). Sem PC/SC não há
  CWs simuladas — o leitor devolve erro.
- **Newcamd real (newcs/cs357x, NCD_524)**: sequência de init de 14 bytes,
  chave de sessão DES (Eurocrypt ECS2), login com password em claro
  (mgcamd) ou MD5-crypt `$1$abcdefgh$` (clientes OSCam), CARD_DATA,
  ECM por tabela 0x80/0x81 e KEEPALIVE. Config `[newcamd] caid` + `key`.
- **DVBAPI real (ca_pmt OSCam)**: o servidor escuta no UNIX socket
  `/tmp/camd.socket`; os descodificadores ligam-se e enviam CA_PMT
  (0x9F8032xx); o servidor responde com DMX_SET_FILTER, CA_SET_PID,
  CA_SET_DESCR_MODE e CA_SET_DESCR (CW par/ímpar). FILTER_DATA processa os ECMs.
- **STAPI real**: dlopen da libstapi.so do STLinux (STPTI_Init/Open/Service
  com DESCR_KEY_SET); sem a biblioteca/hardware ST falha limpo (sem stub).
- **Auto-registo**: `[user_manager] auto_register = 1` cria utilizadores
  desconhecidos (nível USER) e persiste-os no ficheiro.
- **REST**: autenticação Basic configurável (`[rest_api] user/password`).
- **Removido**: CWs simuladas dos leitores local/EMU, leitores de exemplo
  hardcoded, SHA1 de zeros, versão hardcoded na interface web, protocolo
  Newcamd próprio (substituído pelo real).

### 17.3 Novos módulos

| Ficheiro | Função |
|---|---|
| `src/CCshare/cccam3_emu.c/.h` | Motor EMU: SoftCam.Key + dispatcher + BISS |
| `src/CCshare/cccam3_emu_des.c/.h` | DES Viaccess (nc_des), DES OSCam, DES Newcamd |
| `src/CCshare/cccam3_emu_viaccess.c` | Viaccess Via 1/2.6/3 + HD sur-encryption |
| `src/CCshare/cccam3_emu_viaccess_tables.c` | Tabelas de lookup HD (OSCam) |
| `src/hardware/cccam3_smartcard.c/.h` | Leitor local de smartcards via PC/SC |
| `src/network/cccam3_newcamd.c/.h` | Servidor Newcamd real (newcs/cs357x) |
| `.github/workflows/ci.yml` | CI: compila (+PC/SC), self-tests e smoke test em cada push |

### 17.4 Limitações atuais (honestas)

- O wire format do protocolo "CCcam" próprio continua incompatível com
  clientes CCcam comerciais (não é o protocolo binário CCcam real).
- Viaccess local (cartão físico) requer a sequência completa de init da
  sessão; usa-se EMU/leitor remoto para Viaccess.
- STAPI depende da libstapi.so do STLinux e hardware ST.
- Cryptoworks/Nagra/Irdeto/PowerVU na EMU: ainda não implementados
  (Viaccess + BISS disponíveis).

---

## 18. Pacote IPK para Boxes Enigma2 + Correções (2026)

### 18.1 Pacote IPK (`packages/ipk/`)

Distribuição para boxes enigma2 (OpenPLi/OpenATV/OpenViX) via opkg:

| Ficheiro | Função |
|---|---|
| `CONTROL/control` | Metadados opkg (`enigma2-plugin-softcams-cccam3`, arch `all`) |
| `CONTROL/postinst` | Deteta a arquitetura (`uname -m`), copia o binário estático certo para `/usr/bin/cccam3`, cria as configs em `/etc/cccam3/` (sem sobrescrever), ajusta o log para `/var/volatile/log` (tmpfs) e inicia o serviço |
| `CONTROL/prerm` | Para o serviço antes de remover/atualizar |
| `etc/init.d/cccam3` | SysVinit: `start\|stop\|restart\|status` com pidfile |
| `plugin.py` | Entrada **Menu > Plugins > CCcam3** (Iniciar/Parar/Estado) |

- O job `ipk` no workflow de release monta o `.ipk` (formato `ar` +
  `control.tar.gz` + `data.tar.gz`) com os 6 binários + configs de exemplo
  (incluindo `SoftCam.Key`) e anexa-o à release.
- A versão do pacote é derivada da tag da release (`vX.Y.Z` → `X.Y.Z`).

### 18.2 Instalação em boxes sem wget/curl

- `install.sh`: função `download()` com fallback **curl → wget → python**
  (urlretrieve, Python 2 e 3).
- `install.sh` deteta box enigma2 (`command -v opkg`) e instala via `.ipk`.
- Métodos alternativos documentados: `opkg install <URL>` direto ou
  download por Python.

### 18.3 Correções após revisão

- `postinst`: adicionado o mapeamento `armv8l` → armv7 (boxes ARM64 em
  userland 32-bit); `armv6l`/`armhf` mantêm armv7 com aviso de que
  requerem CPU ARMv7.
- `SoftCam.Key` incluído no IPK (`usr/share/cccam3/`) e copiado para
  `/etc/cccam3/` no postinst; `install.sh` também descarrega o
  `SoftCam.Key` de exemplo.
- Versão do `control` e do nome do `.ipk` agora derivados da tag da
  release (fim do 3.0.1 hardcoded no workflow).

---

## 19. Auditoria de Produção — Thread Safety e Robustez (2026)

### 19.1 Bugs reais corrigidos

| # | Bug | Correção |
|---|---|---|
| 1 | **Data races no processamento de ECM**: com a DVBAPI por ligação (uma thread por descodificador), a cache (lista ligada), o card manager (fd/crypto/estado dos leitores) e o hop control passaram a ser mutados por várias threads em simultâneo | Mutex global de ECM (`cccam_ecm_lock/unlock`) a serializar cache + leitores + hops; `cccam_ecm_clean_expired_cache()` no loop principal; ordem de locks documentada (ecm → handshake) |
| 2 | **Race no handshake**: o estado global (chave de sessão/modo) era partilhado entre o login de clientes (loop principal) e o login de leitores remotos (threads de ECM) | `cccam_handshake_lock/unlock` à volta das sequências completas em `handle_client_login` e `remote_ensure_login` |
| 3 | **Double-close + threads órfãs na DVBAPI**: o cleanup fechava os sockets dos clientes e as threads detached fechavam-nos de novo; threads dentro do processamento de ECM podiam sobreviver ao cleanup da cache | Cleanup usa `shutdown()` (nunca `close()`); cada thread fecha o seu fd uma vez sob mutex; condvar espera pelo fim de todas as threads antes do cleanup da cache/leitores |
| 4 | **Logger multi-thread**: linhas intercaladas/UB no va_list | Mutex no `cccam_log` (va_copy antes do consumo) |
| 5 | **Contadores lidos pela API REST** enquanto outras threads escrevem (cache, ECM, utilizadores, clientes, leitores) | `__atomic` em todos os contadores + cargas atómicas nos getters |
| 6 | **SCardTransmit fixo em T=0**: cartões T=1 falhavam no leitor local | Usa o protocolo negociado no `SCardConnect` (T=0 ou T=1) |
| 7 | Interface web: write único podia truncar a página | Loop de escrita parcial com EINTR |
| 8 | `install.sh --from-source`: primeira tentativa de download era um URL inválido (raw + ../archive) | Removida; usa-se diretamente o tarball do GitHub |

### 19.2 Limitações conhecidas (produção)

- O mutex global de ECM serializa pedidos: um leitor remoto lento (connect
  até 5 s, I/O até 10 s) pode atrasar outros ECMs. É limitado e aceitável
  para servidores pequenos/médios; per-reader locking fica para futuro.
- O loop principal continua single-thread: um cliente lento pode bloquear
  até 10 s (SO_RCVTIMEO). Pre-existente.
- Sem rate-limiting no login (bruteforce). Mitigação: passwords fortes e
  `[rest_api] user/password` ativado.
- Em modo DEBUG o log inclui CWs — usar INFO em produção.

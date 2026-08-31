
# CCcam 3.0.1 - Emulator for Share - New Generation

[![Licença GPLv3](https://img.shields.io/badge/Licença-GPLv3-blue.svg)](LICENSE)
[![Versão](https://img.shields.io/badge/Versão-3.0.1-green.svg)](https://github.com/sharillas/CCcam-3.0.1-by-Sharillas)
[![Plataforma](https://img.shields.io/badge/Plataforma-MIPS%20%7C%20ARM%20%7C%20x86_64-lightgrey.svg)]()

---

## 📖 Descrição

**CCcam 3.0.1** é uma reimplementação moderna do protocolo CCcam, desenvolvida do zero com foco em:

- **Segurança** - Suporte a encriptação AES-GCM, RSA, 3DES e RC4
- **Desempenho** - Cache inteligente de Control Words e otimizações de memória
- **Modularidade** - Código organizado por camadas (Core, Network, CCshare, API)
- **Compatibilidade** - Funciona com clientes CCcam existentes e suporte a Newcamd
- **Monitorização** - API REST e Interface Web para gestão remota

---

## ✨ Características

| Característica | Estado | Notas |
|:---|:---:|:---|
| Protocolo CCcam (próprio) | ✅ | Servidor multi-cliente com wire format próprio |
| Protocolo Newcamd real | ✅ | newcs/cs357x (NCD_524): login DES, MD5-crypt, ECM |
| Encriptação RC4 | ✅ | Modo padrão para compatibilidade |
| Encriptação AES-256 | ✅ | Suporte a 128/192/256 bits |
| Encriptação 3DES | ✅ | Modo de segurança adicional |
| Encriptação AES-GCM | ✅ | Tráfego autenticado (confidencialidade + integridade) |
| Criptografia por sessão | ✅ | Chave única por cliente (sem estado global) |
| Handshake seguro | ✅ | PBKDF2-HMAC-SHA256 + AES-GCM (modo moderno), SHA1 (legado) |
| EMU real (SoftCam.Key) | ✅ | Viaccess, BISS, Cryptoworks, PowerVU, Nagra2, Irdeto2 |
| EMM (AU) | ✅ | Reencaminha para leitores remotos + atualiza chaves EMU (Irdeto/PowerVU) |
| Hardening | ✅ | Rate limit de ECMs, anti-bruteforce, filtros de IP |
| Operação | ✅ | Daemon (-d), rotação de log, reload por SIGHUP/REST |
| Controlo do serviço | ✅ | `cccam3 start\|stop\|restart\|status\|log` de qualquer pasta |
| Gestão REST | ✅ | Clientes (kick), utilizadores, reloads, chaves EMU, ficheiros |
| STAPI | ✅ | libstapi.so do STLinux (dlopen) |
| Leitor DVB direto | ✅ | S/S2/C/C2: PAT/SDT/PMT + descrambler |
| Logging configurável | ✅ | Múltiplos níveis (ERROR, WARN, INFO, DEBUG, TRACE) |
| Gestão de utilizadores | ✅ | Níveis de acesso, limites de hops, auto-registo opcional |
| API REST | ✅ | Monitorização com autenticação Basic |
| Interface Web | ✅ | Painel visual: clientes com canal atual, ECM OK/NOK, editor de ficheiros |
| Nomes de canais | ✅ | CCcam.providers + CCcam.channelinfo (19.2E / 13E / 30W + Abertis) |
| CI | ✅ | Compilação + testes automáticos em cada push |
| Documentação | ✅ | Guias de instalação e API |

---

## 🏗️ Arquitetura

```bash
cccam3/
+-- src/
|   +-- core/
|   |   +-- cccam3_server.c
|   |   +-- cccam3_config.c
|   |   +-- cccam3_client.c
|   |   +-- cccam3_logger.c
|   |   +-- cccam3_utils.c
|   |   +-- cccam3_optimizer.c
|   +-- network/
|   |   +-- cccam3_protocol.c
|   |   +-- cccam3_handshake.c
|   |   +-- cccam3_handshake_advanced.c
|   |   +-- cccam3_crypto.c
|   |   +-- cccam3_crypto_advanced.c
|   |   +-- cccam3_newcamd.c          # servidor Newcamd real (newcs/cs357x)
|   +-- hardware/
|   |   +-- cccam3_dvbapi.c           # ca_pmt OSCam (UNIX socket)
|   |   +-- cccam3_stapi.c            # libstapi.so (dlopen)
|   |   +-- cccam3_dvb.c
|   |   +-- cccam3_smartcard.c        # leitor local via PC/SC
|   +-- CCshare/
|   |   +-- cccam3_cache.c
|   |   +-- cccam3_ecm.c
|   |   +-- cccam3_card_manager.c
|   |   +-- cccam3_hop_control.c
|   |   +-- cccam3_user_manager.c
|   |   +-- cccam3_channels.c         # nomes de canais/provedores (painel)
|   |   +-- cccam3_emu.c              # EMU: SoftCam.Key + BISS
|   |   +-- cccam3_emu_des.c          # DES Viaccess/Newcamd
|   |   +-- cccam3_emu_viaccess.c     # Viaccess Via 1/2.6/3 + HD
|   |   +-- cccam3_emu_viaccess_tables.c
|   +-- api/
|       +-- cccam3_rest_api.c         # REST + endpoints de ficheiros
|       +-- cccam3_web_interface.c    # painel web (HTML/JS embutido)
+-- include/
|   +-- cccam3.h
|   +-- cccam3_structs.h
+-- conf/                             # configs de referência
|   +-- cccam3.conf
|   +-- cccam3.users
|   +-- cccam3.readers
|   +-- SoftCam.Key
|   +-- CCcam.providers
|   +-- CCcam.channelinfo
+-- configs/                          # cópias comentadas para leigos
+-- scripts/
|   +-- cccam3                        # wrapper: start|stop|restart|status|log
+-- docs/
|   +-- API.md
|   +-- INSTALL.md
|   +-- HISTORICO.md
+-- web-preview.html                  # pré-visualização do painel
+-- install.sh                        # instalador de 1 comando
+-- Makefile
+-- README.md
+-- LICENSE
```

## 🔒 Segurança

### Modos de Encriptação Suportados

| Modo | Algoritmo | Tamanho da Chave | Estado |
|:---|:---|:---:|:---|
| `NONE` | Sem encriptação | - | ⚠️ Apenas para debug |
| `RC4` | RC4 | 20 bytes | ✅ Estável |
| `AES` | AES (ECB) | 16/24/32 bytes | ✅ Estável |
| `3DES` | Triple DES | 24 bytes | ✅ Estável |
| `AES-GCM` | AES com autenticação | 16/24/32 bytes | ✅ Estável (tráfego autenticado) |

### Handshake de Autenticação

1. Cliente envia **seed** de 16 bytes + credenciais
2. Servidor responde com **seed** de 16 bytes
3. Chave derivada de: `SHA1(client_seed + server_seed + password)` (legado) ou **PBKDF2-HMAC-SHA256** (moderno, 10000 iterações, sal = client_seed + server_seed)
4. No modo moderno o servidor autentica-se com um tag AES-GCM sobre a seed
5. Toda a comunicação posterior é encriptada com a chave de sessão (única por cliente)

---

## 📦 Requisitos

### Dependências

- **OpenSSL** (>= 1.1.0) - Para AES, RC4, 3DES, RSA
- **GCC** (>= 4.8) - Compilador C
- **Make** - Sistema de compilação
- **pthread** - Para suporte a threads (API REST)

### Plataformas Suportadas

| Binário | Arquitetura | Boxes / Servidores compatíveis |
|:---|:---|:---|
| `cccam3-x86_64` | Linux 64 bits | VPS/servidores dedicados (Ubuntu, Debian, CentOS...), PCs, NAS x86_64 |
| `cccam3-x86_32` | Linux 32 bits | VPS/servidores 32 bits antigos |
| `cccam3-armv7` | ARM 32 bits | Raspberry Pi 2/3, boxes DVB ARM 32 bits (Dreambox One/Two, Amiko, Mutant...) |
| `cccam3-aarch64` | ARM 64 bits | Raspberry Pi 4/5, boxes ARM64, servidores ARM64 |
| `cccam3-mipsel` | MIPS 32 LE | Vu+ Duo/Solo/Solo2, Dreambox DM500HD/DM7020HD/DM8000, Gigablue, Zgemma MIPS |
| `cccam3-mips64el` | MIPS 64 LE | Boxes DVB MIPS64 |

---

## 🚀 Instalação Rápida (VPS ou Box)

### 1. Um comando (recomendado)

```bash
curl -fsSL https://raw.githubusercontent.com/sharillas/CCcam-3.0.1-by-Sharillas/main/install.sh | bash
```

O instalador deteta a arquitetura, descarrega o binário da release (ou compila com `--from-source`), instala as configurações em `/etc/cccam3/` (desativa o DVB automaticamente se não houver `/dev/dvb`), instala o serviço systemd e o wrapper de controlo.

### 2. Controlo do serviço (de qualquer pasta)

```bash
cccam3 start                 # inicia o serviço
cccam3 stop                  # para o serviço
cccam3 restart               # reinicia (aplica alterações à config)
cccam3 status                # estado + portas
cccam3 log                   # segue o log em direto (tail -f)
```

### 3. Compilar manualmente

```bash
git clone https://github.com/sharillas/CCcam-3.0.1-by-Sharillas.git
cd CCcam-3.0.1-by-Sharillas
make clean
make
./bin/cccam3 -c conf/cccam3.conf
```

> Ver `conf/` (referência) e `configs/` (cópias comentadas) para TODOS os ficheiros de configuração, com todas as opções explicadas.

---

## 📚 Como Usar

### Como Servidor CCcam

Configure os utilizadores no ficheiro `conf/cccam3.users` e inicie o servidor. Configure os clientes para apontarem para o servidor:

```ini
# Ficheiro C: do cliente (CCcam.cfg)
C: 192.168.1.100 12000 cliente1 senha123
```

### Como Servidor Newcamd

Ative o Newcamd no `conf/cccam3.conf`:

```ini
[newcamd]
enabled = 1
port = 34000
caid = 0500
key = 0102030405060708090a0b0c0d0e
```

A linha CWS do cliente tem de usar a mesma chave DES (os últimos 14 bytes):
`CWS = servidor 34000 user pass 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e`

### Emulação (SoftCam.Key)

Para canais Viaccess ou BISS, ative um leitor EMU no `conf/cccam3.readers` e
coloque as chaves no ficheiro definido em `[emu] key_file`.

### API REST

```bash
curl -u admin:password http://localhost:8080/status      # status do servidor
curl -u admin:password http://localhost:8080/stats       # estatísticas completas
curl -u admin:password http://localhost:8080/stats/cache # estatísticas da cache
curl -u admin:password http://localhost:8080/files       # ficheiros editáveis
```

> Lista completa em [docs/API.md](docs/API.md).

### Interface Web

Abra no navegador: `http://IP-do-servidor:8080/web` e entre com o utilizador/password definidos em `[rest_api]`. O painel mostra:

- Estado do servidor, atividade ECM e cache (gráfico)
- **Clientes ligados** com o **canal atual** (via `CCcam.providers`/`CCcam.channelinfo`) e contadores **ECM OK / ECM NOK**
- Leitores e chaves EMU por sistema
- **Editor de ficheiros**: edita `cccam3.conf`, `cccam3.users`, `cccam3.readers`, `SoftCam.Key`, `CCcam.providers` e `CCcam.channelinfo` diretamente no navegador (guarda com reload automático)

---

## 🛠️ Desenvolvimento

### Compilação para MIPS (Cross-Compile)

```bash
export CROSS_COMPILE=mipsel-linux-
make CC=${CROSS_COMPILE}gcc
```

### Depuração

```bash
make CFLAGS="-g -O0 -DDEBUG"
gdb ./bin/cccam3
```

### Criar Pacote de Distribuição

```bash
make dist
```

---

## 📊 Performance

| Métrica | Valor |
|:---|:---|
| Latência média (zapping) | < 50ms |
| Cache hit rate | > 85% |
| Clientes simultâneos | > 100 |
| Consumo de memória | ~ 10MB |

## 🤝 Contribuição

1. Faça um **Fork** do projeto
2. Crie uma branch para a sua funcionalidade: `git checkout -b feature/nova-func`
3. Faça commit das alterações: `git commit -m 'Adiciona nova funcionalidade'`
4. Faça push para a branch: `git push origin feature/nova-func`
5. Abra um **Pull Request**

## 📄 Licença

Distribuído sob a licença GPLv3. Veja o ficheiro [LICENSE](LICENSE) para mais informações.

## ⚠️ Aviso Legal

Este software é fornecido apenas para fins educacionais e de estudo.
O uso para contornar sistemas de acesso condicional pode ser ilegal em alguns países.
O utilizador é o único responsável pelo uso que faz deste software.

## 🙏 Agradecimentos

- Comunidade **OSCam** - Referência principal
- **OpenSSL** - Biblioteca de criptografia
- Contribuidores do projeto

---

CCcam 3.0.1 - O futuro do Share, by **Sharillas@2026**

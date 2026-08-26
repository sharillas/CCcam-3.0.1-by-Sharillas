
# CCcam 3.0.1 - Emulator for Share - New Generation

[![Licença GPLv3](https://img.shields.io/badge/Licença-GPLv3-blue.svg)](LICENSE)
[![Versão](https://img.shields.io/badge/Versão-3.0.1-green.svg)](https://github.com/seuuser/cccam3)
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
| EMU real (SoftCam.Key) | ✅ | Viaccess (Via 1/2.6/3 + HD) e BISS |
| Leitor local de cartões | ✅ | Smartcards reais via PC/SC (Seca, Conax) |
| Leitores remotos reais | ✅ | TCP com sessão encriptada, timeout e backoff |
| Cache de CWs | ✅ | LRU verdadeiro com timeout configurável |
| DVB-API (ca_pmt OSCam) | ✅ | UNIX socket com CA_PMT/CA_SET_DESCR reais |
| STAPI | ✅ | libstapi.so do STLinux (dlopen) |
| Leitor DVB direto | ✅ | S/S2/C/C2: PAT/SDT/PMT + descrambler |
| Logging configurável | ✅ | Múltiplos níveis (ERROR, WARN, INFO, DEBUG, TRACE) |
| Gestão de utilizadores | ✅ | Níveis de acesso, limites de hops, auto-registo opcional |
| API REST | ✅ | Monitorização com autenticação Basic opcional |
| Interface Web | ✅ | Painel de controlo visual |
| CI | ✅ | Compilação + testes automáticos em cada push |
| Documentação | ✅ | Guias de instalação e API |

---

## 🏗️ Arquitetura
```bash
cccam3/
+-- src/
| +-- core/
| | +-- cccam3_server.c
| | +-- cccam3_config.c
| | +-- cccam3_client.c
| | +-- cccam3_logger.c
| | +-- cccam3_utils.c
| | +-- cccam3_optimizer.c
| +-- network/
| | +-- cccam3_protocol.c
| | +-- cccam3_handshake.c
| | +-- cccam3_handshake_advanced.c
| | +-- cccam3_crypto.c
| | +-- cccam3_crypto_advanced.c
| | +-- cccam3_newcamd.c          # servidor Newcamd real (newcs/cs357x)
| +-- hardware/
| | +-- cccam3_dvbapi.c           # ca_pmt OSCam (UNIX socket)
| | +-- cccam3_stapi.c            # libstapi.so (dlopen)
| | +-- cccam3_dvb.c
| | +-- cccam3_smartcard.c        # leitor local via PC/SC
| +-- CCshare/
| | +-- cccam3_cache.c
| | +-- cccam3_ecm.c
| | +-- cccam3_card_manager.c
| | +-- cccam3_hop_control.c
| | +-- cccam3_user_manager.c
| | +-- cccam3_emu.c              # EMU: SoftCam.Key + BISS
| | +-- cccam3_emu_des.c          # DES Viaccess/Newcamd
| | +-- cccam3_emu_viaccess.c     # Viaccess Via 1/2.6/3 + HD
| | +-- cccam3_emu_viaccess_tables.c
| +-- api/
| +-- cccam3_rest_api.c
| +-- cccam3_web_interface.c
+-- include/
| +-- cccam3.h
| +-- cccam3_structs.h
+-- conf/
| +-- cccam3.conf
| +-- cccam3.users
| +-- cccam3.readers
| +-- SoftCam.Key
+-- docs/
| +-- API.md
| +-- INSTALL.md
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

O instalador deteta a arquitetura, descarrega o binário da release, instala as configurações em `/etc/cccam3/` (desativa o DVB automaticamente se não houver `/dev/dvb`) e instala o serviço. Depois:

```bash
systemctl status cccam3        # estado do serviço
tail -f /var/log/cccam3.log    # log
cccam3 -c /etc/cccam3/cccam3.conf   # correr manualmente
```

> Ver `examples/` na repo para TODOS os ficheiros de configuração de exemplo, com todas as opções comentadas.

### 2. Compilar manualmente

```bash
git clone https://github.com/sharillas/CCcam-3.0.1-by-Sharillas.git
cd CCcam-3.0.1-by-Sharillas
make clean
make
./bin/cccam3 -c conf/cccam3.conf
```
📚 Como Usar
Como Servidor CCcam
Configure os utilizadores no ficheiro conf/cccam3.users:


```ini
[user]
username = cliente1
password = senha123
hops = 1
```
Inicie o servidor

Configure os clientes para apontarem para o servidor:


```bash
# Ficheiro C: /etc/CCcam.cfg
C: 192.168.1.100 12000 cliente1 senha123
```
Como Servidor Newcamd
Ative o Newcamd no conf/cccam3.conf:

```ini
[newcamd]
enabled = 1
port = 34000
caid = 0500
key = 0102030405060708090a0b0c0d0e
```

Configure os clientes Newcamd para apontarem para o servidor na porta 34000.
A linha CWS do cliente tem de usar a mesma chave DES (os últimos 14 bytes):
`CWS = servidor 34000 user pass 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e`

Emulação (SoftCam.Key)
Para canais Viaccess ou BISS, ative um leitor EMU no conf/cccam3.readers e
coloque as chaves no ficheiro definido em `[emu] key_file`.

API REST
# Status do servidor
```bash
curl http://localhost:8080/status
```

# Estatísticas completas
```bash
curl http://localhost:8080/stats
```

# Estatísticas da cache
```bash
curl http://localhost:8080/stats/cache
```
Interface Web
Abra no navegador: http://localhost:8080/web

🛠️ Desenvolvimento
Compilação para MIPS (Cross-Compile)
```bash
export CROSS_COMPILE=mipsel-linux-
make CC=${CROSS_COMPILE}gcc
```
Depuração
```bash
make CFLAGS="-g -O0 -DDEBUG"
gdb ./bin/cccam3
```
Gerar Documentação
```bash
make docs
```
Criar Pacote de Distribuição
```bash
make dist
```

📊 Performance
Métrica	Valor
Latência média (zapping)	< 50ms
Cache hit rate	> 85%
Clientes simultâneos	> 100
Consumo de memória	~ 10MB
🤝 Contribuição
Faça um Fork do projeto

Crie uma branch para a sua funcionalidade 
```bash
git checkout -b feature/nova-func
```
Commit as suas alterações
```bash
git commit -m 'Adiciona nova funcionalidade'
```
Push para a branch 
```bash
git push origin feature/nova-func
```
Abra um Pull Request

📄 Licença
Distribuído sob a licença GPLv3. Veja o ficheiro LICENSE para mais informações.

⚠️ Aviso Legal
Este software é fornecido apenas para fins educacionais e de estudo. 
O uso para contornar sistemas de acesso condicional pode ser ilegal em alguns países. 
O utilizador é o único responsável pelo uso que faz deste software.

🙏 Agradecimentos
Comunidade OSCam - Referência principal

OpenSSL - Biblioteca de criptografia

Contribuidores do projeto

CCcam 3.0.1 - O futuro do Share, em Desenvolvimento, by Sharillas@2026

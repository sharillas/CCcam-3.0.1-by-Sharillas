
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
| Protocolo CCcam 2.0.9+ | ✅ | Compatível com clientes antigos |
| Protocolo Newcamd | ✅ | Suporte a clientes Newcamd |
| Encriptação RC4 | ✅ | Modo padrão para compatibilidade |
| Encriptação AES-256 | ✅ | Suporte a 128/256 bits |
| Encriptação 3DES | ✅ | Modo de segurança adicional |
| Encriptação AES-GCM | ✅ | Modo autenticado (confidencialidade + integridade) |
| Troca de chaves RSA | ✅ | Handshake seguro com RSA 2048 bits |
| Cache de CWs | ✅ | Reduz latência no zapping |
| DVB-API / STAPI | ✅ | Interface com hardware |
| Logging configurável | ✅ | Múltiplos níveis (ERROR, WARN, INFO, DEBUG, TRACE) |
| Gestão de utilizadores | ✅ | Níveis de acesso e limites de hops por utilizador |
| API REST | ✅ | Monitorização e gestão remota |
| Interface Web | ✅ | Painel de controlo visual |
| Optimizer | ✅ | Gestão de memória, timeouts, failover e balanceamento de carga |
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
| | +-- cccam3_protocol_newcamd.c
| +-- hardware/
| | +-- cccam3_dvbapi.c
| | +-- cccam3_stapi.c
| +-- CCshare/
| | +-- cccam3_cache.c
| | +-- cccam3_ecm.c
| | +-- cccam3_card_manager.c
| | +-- cccam3_hop_control.c
| | +-- cccam3_user_manager.c
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
| `RC4` | RC4-like | 20 bytes | ✅ Estável |
| `AES` | AES-256 | 32 bytes | ✅ Estável |
| `3DES` | Triple DES | 24 bytes | ✅ Estável |
| `AES-GCM` | AES com autenticação | 32 bytes | ✅ Estável |
| `RSA` | RSA + AES-GCM | 2048 bits | ✅ Estável |

### Handshake de Autenticação

1. Cliente envia **seed** de 16 bytes + credenciais
2. Servidor responde com **seed** de 16 bytes
3. Chave derivada de: `SHA1(client_seed + server_seed + password)` (legado) ou **RSA + AES-GCM** (moderno)
4. Toda a comunicação posterior é encriptada

---

## 📦 Requisitos

### Dependências

- **OpenSSL** (>= 1.1.0) - Para AES, RC4, 3DES, RSA
- **GCC** (>= 4.8) - Compilador C
- **Make** - Sistema de compilação
- **pthread** - Para suporte a threads (API REST)

### Plataformas Suportadas

| Plataforma | Arquitetura | Estado |
|:---|:---|:---:|
| Linux (x86_64) | x86_64 | ✅ Testado |
| Linux (ARM) | ARMv7/ARMv8 | 🚧 Em teste |
| Linux (MIPS) | MIPS32 | 🚧 Em teste |
| OpenWRT | MIPS/ARM | 🚧 Em teste |

---

## 🚀 Instalação Rápida

### 1. Clonar o Repositório

```bash
git clone https://github.com/seuuser/cccam3.git
cd cccam3
```
2. Compilar

```bash
make clean
make

```
3.Configurar
Edite o ficheiro conf/cccam3.conf com as suas definições:


```ini
[global]
port = 12000
max_clients = 100

[logging]
level = 2

[cache]
enabled = 1
timeout = 10

[rest_api]
port = 8080
enabled = 1

[newcamd]
enabled = 1
port = 34000
```
4. Executar

```bash
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
```
Configure os clientes Newcamd para apontarem para o servidor na porta 34000.

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

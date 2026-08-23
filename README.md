# CCcam 3.0.1 - Emulator - New Generation

[![Licença GPLv3](https://img.shields.io/badge/Licença-GPLv3-blue.svg)](LICENSE)
[![Versão](https://img.shields.io/badge/Versão-3.0.0-green.svg)](https://github.com/seuuser/cccam3)
[![Plataforma](https://img.shields.io/badge/Plataforma-MIPS%20%7C%20ARM%20%7C%20x86_64-lightgrey.svg)]()

---

## 📖 Descrição

**CCcam3** é uma reimplementação moderna do protocolo CCcam, desenvolvida do zero com foco em:

- **Segurança** - Suporte a encriptação AES, 3DES e RC4
- **Desempenho** - Cache inteligente de Control Words
- **Modularidade** - Código organizado por camadas
- **Compatibilidade** - Funciona com clientes CCcam existentes

---

## ✨ Características

| Característica | Estado | Notas |
|:---|:---:|:---|
| Protocolo CCcam 2.0.9+ | ✅ | Compatível com clientes antigos |
| Encriptação RC4 | ✅ | Modo padrão para compatibilidade |
| Encriptação AES-256 | ✅ | Suporte a 128/256 bits |
| Encriptação 3DES | ✅ | Modo de segurança adicional |
| Encriptação AES-GCM | 🚧 | Em desenvolvimento |
| Troca de chaves RSA | 🚧 | Planeado para futura versão |
| Cache de CWs | ✅ | Reduz latência no zapping |
| DVB-API / STAPI | 🚧 | Interface com hardware |
| Logging configurável | ✅ | Múltiplos níveis |
| Gestão de utilizadores | 🚧 | Em desenvolvimento |

---

## 🏗️ Arquitetura

```
CCcam-3.0.1-by-Sharillas/
---------------------------
cccam3/
+-- src/
|   +-- core/
|   |   +-- cccam3_server.c
|   |   +-- cccam3_config.c
|   |   +-- cccam3_client.c
|   |   +-- cccam3_logger.c
|   |   +-- cccam3_utils.c
|   +-- network/
|   |   +-- cccam3_protocol.c
|   |   +-- cccam3_handshake.c
|   |   +-- cccam3_crypto.c
|   +-- hardware/
|   |   +-- cccam3_dvbapi.c
|   |   +-- cccam3_stapi.c
|   +-- CCshare/                         # <-- NOVO NOME
|       +-- cccam3_cache.c
+-- include/
|   +-- cccam3.h
|   +-- cccam3_structs.h
+-- conf/
|   +-- cccam3.conf
|   +-- cccam3.user
+-- docs/
```

## 🔒 Segurança

### Modos de Encriptação Suportados

| Modo | Algoritmo | Tamanho da Chave | Estado |
|:---|:---|:---:|:---|
| `NONE` | Sem encriptação | - | ⚠️ Apenas para debug |
| `RC4` | RC4-like | 20 bytes | ✅ Estável |
| `AES` | AES-256 | 32 bytes | ✅ Estável |
| `3DES` | Triple DES | 24 bytes | ✅ Estável |
| `AES-GCM` | AES com autenticação | 32 bytes | 🚧 Em dev |

### Handshake de Autenticação

1. Cliente envia **seed** de 16 bytes + credenciais
2. Servidor responde com **seed** de 16 bytes
3. Chave derivada de: `SHA1(client_seed + server_seed + password)`
4. Toda a comunicação posterior é encriptada

---

## 📦 Requisitos

### Dependências

- **OpenSSL** (>= 1.1.0) - Para AES, RC4, 3DES
- **GCC** (>= 4.8) - Compilador C
- **Make** - Sistema de compilação
- **CMake** (opcional) - Alternativa de compilação

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

    git clone https://github.com/seuuser/cccam3.git
    cd cccam3

### 2. Compilar

    make clean
    make

### 3. Configurar

Edite o ficheiro `conf/cccam3.conf` com as suas definições:

    [global]
    port = 12000
    max_clients = 100

    [logging]
    level = 2

    [cache]
    enabled = 1
    timeout = 10

### 4. Executar

    ./bin/cccam3 -c conf/cccam3.conf

---

## 📚 Como Usar

### Como Servidor

1. Configure os utilizadores no ficheiro `conf/cccam3.user`:

    [user]
    username = cliente1
    password = senha123
    hops = 1

2. Inicie o servidor

3. Configure os clientes para apontarem para o servidor:

    # Ficheiro C: /etc/CCcam.cfg
    C: 192.168.1.100 12000 cliente1 senha123

### Como Cliente

1. Configure o servidor remoto no ficheiro `conf/cccam3.server`:

    [server]
    host = servidor.remoto.com
    port = 12000
    username = meu_user
    password = minha_senha

2. Inicie o cliente

---

## 🛠️ Desenvolvimento

### Compilação para MIPS (Cross-Compile)

    export CROSS_COMPILE=mipsel-linux-
    make CC=${CROSS_COMPILE}gcc

### Depuração

    make CFLAGS="-g -O0 -DDEBUG"
    gdb ./bin/cccam3

### Executar Testes

    make test
    ./bin/test_cccam3

---

## 📊 Performance

| Métrica | Valor |
|:---|:---:|
| Latência média (zapping) | < 50ms |
| Cache hit rate | > 85% |
| Clientes simultâneos | > 100 |
| Consumo de memória | ~ 10MB |

---

## 🤝 Contribuição

1. Faça um **Fork** do projeto
2. Crie uma **branch** para a sua funcionalidade (`git checkout -b feature/nova-func`)
3. Commit as suas alterações (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-func`)
5. Abra um **Pull Request**

---

## 📄 Licença

Distribuído sob a licença **GPLv3**. Veja o ficheiro `LICENSE` para mais informações.

---

## ⚠️ Aviso Legal

Este software é fornecido **apenas para fins educacionais e de estudo**. O uso para contornar sistemas de acesso condicional pode ser **ilegal** em alguns países. O utilizador é o único responsável pelo uso que faz deste software.

---

## 📞 Suporte

- **Issues**: [GitHub Issues]()
- **Wiki**: [Documentação Completa]()
- **Discord**: [Servidor da Comunidade]()

---

## 🙏 Agradecimentos

- Comunidade OSCam - Referência principal
- OpenSSL - Biblioteca de criptografia
- Contribuidores do projeto

---

**CCcam 3.0.1** - *O futuro da partilha de cartões*

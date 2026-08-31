# Guia de Instalação do CCcam 3.0.1

## Pré-requisitos

- **Sistema Operativo:** Linux (x86_64, ARM, MIPS) — VPS ou box DVB
- **Compilador (apenas se compilar):** GCC (>= 4.8)
- **Bibliotecas:** OpenSSL (>= 1.1.0), pthread
- **Ferramentas:** Make, Git (opcional)

---

## Instalação Rápida (VPS ou Box) — 1 comando

```bash
curl -fsSL https://raw.githubusercontent.com/sharillas/CCcam-3.0.1-by-Sharillas/main/install.sh | bash
```

O instalador:

1. Deteta a arquitetura (x86_64, x86_32, armv7, aarch64, mipsel, mips64el)
2. Descarrega o binário da release v3.0.1 (ou compila da fonte com `--from-source`)
3. Instala em `/usr/local/bin/cccam3.bin` + wrapper de controlo `/usr/local/bin/cccam3`
4. Cria as configurações em `/etc/cccam3/` (não sobrescreve as existentes)
5. Desativa o leitor DVB automaticamente se não houver `/dev/dvb` (VPS)
6. Instala o serviço systemd (ou init.d) e inicia-o

### Opções do instalador

```bash
# compilar a partir do código-fonte em vez do binário da release
curl -fsSL https://raw.githubusercontent.com/sharillas/CCcam-3.0.1-by-Sharillas/main/install.sh | bash -s -- --from-source

# instalar só binário + configs (sem serviço)
curl -fsSL https://raw.githubusercontent.com/sharillas/CCcam-3.0.1-by-Sharillas/main/install.sh | bash -s -- --no-service
```

---

## Controlo do Serviço

Depois de instalado, controla o serviço de qualquer pasta:

```bash
cccam3 start      # inicia
cccam3 stop       # para
cccam3 restart    # reinicia (aplica alterações à config)
cccam3 status     # estado do serviço
cccam3 log        # segue o log em direto
```

Equivalente via systemd:

```bash
systemctl start|stop|restart|status cccam3
```

---

## Instalação Manual (a partir do código)

### 1. Clonar e compilar

```bash
git clone https://github.com/sharillas/CCcam-3.0.1-by-Sharillas.git
cd CCcam-3.0.1-by-Sharillas
make clean
make
```

### 2. Instalar

```bash
sudo make install
```

O binário fica em `/usr/local/bin/cccam3`.

---

## Configuração

### Ficheiro principal — `/etc/cccam3/cccam3.conf`

```ini
[global]
port = 12000                    # porta CCcam (clientes)
server_name = CCcam3
max_clients = 100
providers_file = conf/CCcam.providers        # nomes de provedores (painel)
channelinfo_file = conf/CCcam.channelinfo    # nomes de canais (painel)

[logging]
level = 2
file = /var/log/cccam3.log

[cache]
enabled = 1
timeout = 10

[hop_control]
max_hops = 3
timeout = 60
block_loops = 1

[rest_api]
enabled = 1
port = 8080                     # painel web + API
user = admin                    # login do painel
password = muda-me              # MUDAR SEMPRE

[newcamd]
enabled = 1
port = 34000                    # porta Newcamd
caid = 0500
key = 0102030405060708090a0b0c0d0e

[user_manager]
enabled = 1
file = conf/cccam3.users
auto_register = 0
```

> Em produção, muda as portas para valores que não colidam com outros
> serviços e define credenciais fortes em `[rest_api]`.

### Utilizadores — `/etc/cccam3/cccam3.users`

```ini
[admin]
password = admin123
level = 3
max_hops = 0

[cliente1]
password = 123456
level = 1
max_hops = 2
```

### Leitores — `/etc/cccam3/cccam3.readers`

```ini
[Local_Reader]
type = local
caid = 0100
provid = 0000
hop = 1
priority = 0
enabled = 1

[Remote_Reader]
type = remote
caid = 0500
provid = 0000
hop = 2
priority = 1
enabled = 1
remote_host = 127.0.0.1
remote_port = 12001
remote_user = user
remote_pass = pass
```

### Canais/Provedores (nomes no painel)

- `/etc/cccam3/CCcam.providers` — formato `caid:provid:nome`
- `/etc/cccam3/CCcam.channelinfo` — formato `caid:provid:sid:nome` (caid/provid `0000` = wildcard)

Já vêm com uma base curada para Astra 19.2E, Hotbird 13E e Hispasat 30W (incluindo os TDT espanhóis Abertis). Os SIDs podem mudar com o tempo — atualizar a partir dos pacotes da comunidade quando necessário.

> Todos os ficheiros podem ser editados pelo painel web (secção Ficheiros).

---

## Execução

### Modo normal

```bash
cccam3 -c /etc/cccam3/cccam3.conf
```

### Modo debug

```bash
cccam3 -c /etc/cccam3/cccam3.conf -v
```

### Como serviço (systemd) — instalado automaticamente

```ini
[Unit]
Description=CCcam3 server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/cccam3 -c /etc/cccam3/cccam3.conf
Restart=always
RestartSec=5
KillMode=process

[Install]
WantedBy=multi-user.target
```

---

## Verificação

```bash
cccam3 status                                   # serviço ativo?
curl -u admin:password http://localhost:8080/status   # API REST
```

Abra o painel web no navegador: `http://IP-do-servidor:8080/web`

---

## Desinstalação

```bash
systemctl stop cccam3
systemctl disable cccam3
rm -f /etc/systemd/system/cccam3.service /usr/local/bin/cccam3 /usr/local/bin/cccam3.bin
rm -rf /etc/cccam3
systemctl daemon-reload
```

---

## Compilação Cruzada

```bash
# MIPS
make CC=mipsel-linux-gnu-gcc

# ARM
make CC=arm-linux-gnueabihf-gcc
```

---

## Resolução de Problemas

### "Falha ao bindar porta"

A porta já está a ser usada por outro processo:

```bash
sudo ss -tlnp | grep <porta>
```

Muda a porta no `cccam3.conf` e reinicia com `cccam3 restart`.

### "OpenSSL não encontrado"

```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev

# RHEL/CentOS
sudo yum install openssl-devel
```

### "Permissão negada"

Executa com permissões adequadas (root ou utilizador com acesso aos dispositivos):

```bash
sudo ./bin/cccam3 -c conf/cccam3.conf
```

### Painel web não abre

1. Confirma que `[rest_api] enabled = 1` e a porta está livre
2. Abre a porta na firewall (`ufw allow 8080/tcp`)
3. Verifica o log: `cccam3 log`

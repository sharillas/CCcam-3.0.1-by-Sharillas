markdown
# Guia de Instalação do CCcam3

## Pré-requisitos

- **Sistema Operativo:** Linux (x86_64, ARM, MIPS)
- **Compilador:** GCC (>= 4.8)
- **Bibliotecas:** OpenSSL (>= 1.1.0), pthread
- **Ferramentas:** Make, Git (opcional)

## Instalação a Partir do Código Fonte

### 1. Clonar o Repositório (ou extrair o pacote)

```bash
git clone https://github.com/seuuser/cccam3.git
cd cccam3
```
2. Compilar
```bash
make clean
make
```
3. Instalar
```bash
make install
```
O binário será instalado em /usr/local/bin/cccam3.

Configuração
Ficheiro Principal de Configuração
Editar o ficheiro conf/cccam3.conf:

```ini
[global]
port = 12000
server_name = CCcam3
max_clients = 100

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
port = 8080
enabled = 1

[web_interface]
enabled = 1
path = /web

[user_manager]
enabled = 1
file = conf/cccam3.users
auto_register = 0
```
Ficheiro de Utilizadores
Editar o ficheiro conf/cccam3.users:

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
Ficheiro de Leitores
Editar o ficheiro conf/cccam3.readers:

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
Execução
Modo Normal
```bash
cccam3 -c /path/to/cccam3.conf
```
Modo Debug
```bash
cccam3 -c conf/cccam3.conf -v
```
Como Serviço (Systemd)
Criar o ficheiro /etc/systemd/system/cccam3.service:

```ini
[Unit]
Description=CCcam3 Server
After=network.target

[Service]
ExecStart=/usr/local/bin/cccam3 -c /etc/cccam3/cccam3.conf
Restart=always
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
```
Ativar e iniciar o serviço:

```bash
systemctl enable cccam3
systemctl start cccam3
```
Verificação
```bash
# Verificar se o servidor está em execução
ps aux | grep cccam3
```
# Verificar a API REST
```bash
curl http://localhost:8080/status
```
Desinstalação
```bash
make uninstall
```
Compilação Cruzada para MIPS
bash
make mips
Compilação Cruzada para ARM
```bash
make arm
```
Resolução de Problemas
Erro: "Falha ao bindar porta"
Verifique se a porta já está a ser usada:

```bash
sudo netstat -tulpn | grep 12000
```
Erro: "OpenSSL não encontrado"

Instale o OpenSSL:


# Debian/Ubuntu
```bash
sudo apt-get install libssl-dev
```

# RHEL/CentOS
```bash
sudo yum install openssl-devel
```
Erro: "Permissão negada"

Execute com permissões adequadas ou como root:

```bash
sudo ./bin/cccam3 -c conf/cccam3.conf
```

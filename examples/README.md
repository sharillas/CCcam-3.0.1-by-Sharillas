# Exemplos de Configuração CCcam3

Esta pasta contém exemplos de TODOS os ficheiros de configuração do projeto, com todas as opções possíveis e descrição detalhada de cada uma.

| Ficheiro | O que é |
|---|---|
| `cccam3.conf` | Configuração principal do servidor — TODAS as secções e opções comentadas ([global], [logging], [cache], [security], [hop_control], [rest_api], [web_interface], [user_manager], [newcamd], [dvbapi], [dvb], [stapi]) |
| `cccam3.users` | Lista de utilizadores (password, nível de acesso, limite de hops) |
| `cccam3.readers` | Lista de leitores de CWs (local / remoto / emu) com todas as opções |
| `cccam3.service` | Unidade systemd para correr o servidor como serviço |

## Como usar

Cópia para produção:

```bash
sudo mkdir -p /etc/cccam3
sudo cp examples/cccam3.conf  /etc/cccam3/cccam3.conf
sudo cp examples/cccam3.users  /etc/cccam3/cccam3.users
sudo cp examples/cccam3.readers /etc/cccam3/cccam3.readers
```

Depois edita o que for preciso e arranca:

```bash
cccam3 -c /etc/cccam3/cccam3.conf
```

> O instalador automático (`install.sh` na raiz da repo) faz tudo isto por ti com um único comando.

## Opções da linha de comandos do CCcam3

```
Uso: cccam3 [opções]
  -c <file>   Ficheiro de configuração (por omissão: conf/cccam3.conf)
  -h          Mostra ajuda
  -t          Executa os testes automáticos
  -v          Mostra a versão
```

## Notas

- Booleanos aceitam `1`, `yes` ou `true` (e `0`, `no`, `false`)
- CAID/PROVID nos readers são hexadecimais
- Se os ficheiros de users/readers não existirem no caminho configurado, o servidor procura também em `/etc/cccam3/`
- Sem ficheiro de utilizadores válido, é criado o utilizador por omissão `admin` / `admin123` (alterar!)

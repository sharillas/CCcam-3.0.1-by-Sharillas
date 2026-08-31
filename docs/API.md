# API REST do CCcam 3.0.1 - Documentação Completa

## Visão Geral

A API REST do CCcam3 permite monitorizar e gerir o servidor remotamente através de requisições HTTP. Todas as respostas são em formato **JSON válido**.

## Autenticação

Se a configuração `[rest_api]` tiver `user` e `password` definidos, todos os
endpoints exigem autenticação HTTP Basic — exceto a página `/web` (estática),
cujo login é feito no formulário do próprio painel:

```ini
[rest_api]
enabled = 1
port = 8080
user = admin
password = muda-me
```

```bash
curl -u admin:muda-me http://localhost:8080/status
```

Sem `user`/`password` configurados, a API fica aberta (avisado no log).

## Endpoints Disponíveis

### 1. Status do Servidor

**Endpoint:** `GET /status` ou `GET /`

**Descrição:** Retorna o estado atual do servidor.

**Resposta de Exemplo:**
```json
{
  "server": {
    "name": "CCcam3",
    "version": "3.0.1",
    "status": "online",
    "uptime": "2026-09-01 14:30:00",
    "clients": 5,
    "hop_limit": 3,
    "port": 12000,
    "newcamd_port": 34000,
    "rest_port": 8080
  }
}
```

### 2. Estatísticas Completas

**Endpoint:** `GET /stats` ou `GET /stats/all`

**Descrição:** Retorna todas as estatísticas disponíveis (servidor, cache, ECM, leitores).

**Resposta de Exemplo:**
```json
{
  "timestamp": 1234567890,
  "server": { "name": "CCcam3", "version": "3.0.1", "status": "online",
              "uptime": "2026-09-01 14:30:00", "clients": 5,
              "hop_limit": 3, "port": 12000 },
  "cache": { "entries": 42, "hits": 1250, "misses": 320, "hit_ratio": 79.62 },
  "ecm": { "total_requests": 1570, "cache_hits": 1250, "cache_misses": 320,
           "reader_success": 280, "reader_fail": 40, "cache_hit_ratio": 79.62 },
  "readers": { "total": 3, "active": 2, "local": 1, "remote": 2 }
}
```

### 3. Estatísticas da Cache

**Endpoint:** `GET /stats/cache`

```json
{
  "cache": {
    "entries": 42,
    "hits": 1250,
    "misses": 320,
    "hit_ratio": 79.62
  }
}
```

### 4. Estatísticas ECM

**Endpoint:** `GET /stats/ecm`

```json
{
  "ecm": {
    "total_requests": 1570,
    "cache_hits": 1250,
    "cache_misses": 320,
    "reader_success": 280,
    "reader_fail": 40,
    "cache_hit_ratio": 79.62
  }
}
```

### 5. Estatísticas dos Leitores

**Endpoint:** `GET /stats/readers`

```json
{
  "readers": {
    "total": 3,
    "active": 2,
    "local": 1,
    "remote": 2
  }
}
```

### 6. Clientes Ligados

**Endpoint:** `GET /clients`

**Descrição:** Lista os clientes ligados com o canal atual (via
`CCcam.providers`/`CCcam.channelinfo`) e contadores de ECMs.

```json
{
  "clients": {
    "count": 2,
    "list": [
      {
        "id": 101,
        "user": "cliente1",
        "ip": "192.168.1.40",
        "newcamd": 0,
        "authenticated": 1,
        "connected_at": 1234567890,
        "ecm_total": 4820,
        "ecm_ok": 4710,
        "ecm_fail": 110,
        "sid": 26,
        "caid": 1810,
        "channel": "TF1 HD",
        "provider": "TNTSAT"
      }
    ]
  }
}
```

### 7. Leitores (lista detalhada)

**Endpoint:** `GET /readers`

```json
{
  "readers_list": {
    "count": 3,
    "list": [
      { "name": "EMU_Reader", "type": 2, "state": 1, "caid": 0,
        "hop": 0, "priority": 0, "ecm_requests": 1204,
        "ecm_success": 1180, "ecm_fail": 24 }
    ]
  }
}
```

### 8. Utilizadores

**Endpoint:** `GET /users`

```json
{
  "users": {
    "count": 2,
    "list": [
      { "name": "cliente1", "level": 1, "max_hops": 2, "enabled": 1,
        "logins": 12, "ecm": 4820, "ecm_ok": 4710 }
    ]
  }
}
```

### 9. Chaves EMU

**Endpoint:** `GET /emu/keys`

```json
{
  "emu": {
    "total": 18, "biss": 7, "viaccess": 4, "cryptoworks": 2,
    "powervu": 3, "nagra": 1, "irdeto": 1
  }
}
```

### 10. Expulsar Cliente

**Endpoint:** `GET /clients/kick?id=<id>`

**Descrição:** Desliga um cliente pelo ID (o mesmo da lista de `/clients`).

### 11. Ficheiros Editáveis

**Endpoint:** `GET /files`

**Descrição:** Lista os ficheiros editáveis no painel.

```json
{
  "files": {
    "list": [
      { "name": "cccam3.conf", "path": "/etc/cccam3/cccam3.conf", "size": 2048 },
      { "name": "cccam3.users", "path": "/etc/cccam3/cccam3.users", "size": 512 }
    ]
  }
}
```

Ficheiros disponíveis: `cccam3.conf`, `cccam3.users`, `cccam3.readers`,
`SoftCam.Key`, `CCcam.providers`, `CCcam.channelinfo`.

### 12. Ler um Ficheiro

**Endpoint:** `GET /files/get?name=<nome>`

```json
{
  "result": "ok",
  "name": "cccam3.users",
  "path": "/etc/cccam3/cccam3.users",
  "content": "[admin]\npassword = admin123\n..."
}
```

### 13. Guardar um Ficheiro

**Endpoint:** `POST /files/save?name=<nome>` — corpo = conteúdo do ficheiro

**Descrição:** Escreve o ficheiro (escrita atómica: tmp + rename) e recarrega
automaticamente o que for aplicável:

| Ficheiro | Ação ao guardar |
|:---|:---|
| `cccam3.users` | recarrega utilizadores |
| `cccam3.readers` | recarrega leitores |
| `SoftCam.Key` | recarrega chaves EMU |
| `CCcam.providers` / `CCcam.channelinfo` | recarrega nomes de canais |
| `cccam3.conf` | guardado (requer `cccam3 restart`) |

```json
{ "result": "ok", "action": "users_reloaded" }
```

### 14. Interface Web

**Endpoint:** `GET /web` ou `GET /web/`

**Descrição:** Retorna a página HTML do painel (pública; o login é no formulário).

---

## Códigos de Resposta

| Código | Descrição |
|:---|:---|
| 200 OK | Requisição processada com sucesso |
| 400 Bad Request | Requisição malformada |
| 401 Unauthorized | Credenciais em falta/inválidas (inclui `WWW-Authenticate`) |
| 404 Not Found | Endpoint não encontrado |

---

## Exemplo de Uso com curl

```bash
# Status do servidor
curl -u admin:muda-me http://localhost:8080/status

# Estatísticas completas
curl -u admin:muda-me http://localhost:8080/stats

# Estatísticas da cache / ECM / leitores
curl -u admin:muda-me http://localhost:8080/stats/cache
curl -u admin:muda-me http://localhost:8080/stats/ecm
curl -u admin:muda-me http://localhost:8080/stats/readers

# Clientes ligados (com canal atual e ECM OK/NOK)
curl -u admin:muda-me http://localhost:8080/clients

# Expulsar o cliente 101
curl -u admin:muda-me "http://localhost:8080/clients/kick?id=101"

# Listar ficheiros e ler um ficheiro
curl -u admin:muda-me http://localhost:8080/files
curl -u admin:muda-me "http://localhost:8080/files/get?name=cccam3.users"

# Guardar um ficheiro (POST com o conteúdo no corpo)
curl -u admin:muda-me -X POST -d "[admin]
password = nova" "http://localhost:8080/files/save?name=cccam3.users"

# Interface web
curl http://localhost:8080/web
```

# API REST do CCcam3 - Documentação Completa

## Visão Geral
A API REST do CCcam3 permite monitorizar e gerir o servidor remotamente através de requisições HTTP. Todas as respostas são em formato JSON.

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
    "uptime": "2025-01-15 14:30:00",
    "clients": 5,
    "hop_limit": 3,
    "port": 12000
  }
}

```
2. Estatísticas Completas
Endpoint: GET /stats ou GET /stats/all

Descrição: Retorna todas as estatísticas disponíveis (servidor, cache, ECM, leitores).

Resposta de Exemplo:

```json
{
  "timestamp": 1234567890,
  "server": {
    "name": "CCcam3",
    "version": "3.0.1",
    "status": "online",
    "uptime": "2025-01-15 14:30:00",
    "clients": 5,
    "hop_limit": 3,
    "port": 12000
  },
  "cache": {
    "entries": 42,
    "hits": 1250,
    "misses": 320,
    "hit_ratio": 79.62
  },
  "ecm": {
    "total_requests": 1570,
    "cache_hits": 1250,
    "cache_misses": 320,
    "reader_success": 280,
    "reader_fail": 40,
    "cache_hit_ratio": 79.62
  },
  "readers": {
    "total": 3,
    "active": 2,
    "local": 1,
    "remote": 2
  }
}

```
3. Estatísticas da Cache
Endpoint: GET /stats/cache

Descrição: Retorna estatísticas detalhadas da cache de Control Words.

Resposta de Exemplo:

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
4. Estatísticas ECM
Endpoint: GET /stats/ecm

Descrição: Retorna estatísticas de processamento de ECM.

Resposta de Exemplo:

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
5. Estatísticas dos Leitores
Endpoint: GET /stats/readers

Descrição: Retorna estatísticas dos leitores configurados.

Resposta de Exemplo:

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
6. Interface Web
Endpoint: GET /web ou GET /web/

Descrição: Retorna a página HTML da interface web de monitorização.

Códigos de Resposta
Código	Descrição

200 OK	Requisição processada com sucesso.

400 Bad Request	Requisição malformada.

404 Not Found	Endpoint não encontrado.


Exemplo de Uso com curl
```bash
# Status do servidor
curl http://localhost:8080/status


# Estatísticas completas
curl http://localhost:8080/stats

# Estatísticas da cache
curl http://localhost:8080/stats/cache

# Estatísticas ECM
curl http://localhost:8080/stats/ecm

# Estatísticas dos leitores
curl http://localhost:8080/stats/readers

# Interface web
curl http://localhost:8080/web
```

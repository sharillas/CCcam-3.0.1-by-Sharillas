# API REST do CCcam3

## Endpoints

### GET /status
Retorna o estado do servidor.

**Resposta:**
```json
{
  "server": {
    "name": "CCcam3",
    "version": "3.0.1",
    "status": "online",
    "clients": 5,
    "hop_limit": 3,
    "port": 12000
  }
}

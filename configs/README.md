# 📁 Configs do CCcam3 — Guia para Leigos

Esta pasta tem **todos os ficheiros de configuração do CCcam3**, com cada
opção explicada em linguagem simples. É a única pasta que precisas de
copiar para o teu servidor.

## O que é cada ficheiro? (explicação simples)

| Ficheiro | Para que serve | Preciso de mexer? |
|---|---|---|
| `cccam3.conf` | As "definições gerais" do servidor: portas, logs, segurança, leitor de antena | ✅ Sim — é aqui que se configura quase tudo |
| `cccam3.users` | A lista de pessoas (clientes) que podem ligar-se ao teu servidor | ✅ Sim — adicionas aqui cada amigo/cliente |
| `cccam3.readers` | De onde vêm as "chaves" (CWs): de outro servidor (share), de um cartão real ou das chaves EMU | ✅ Sim — sem leitores, o servidor não abre canais |
| `SoftCam.Key` | As chaves de emulação (BISS, Viaccess, PowerVU, etc.) — é isto que abre os canais sem cartão | ✅ Sim — colas aqui as chaves que arranjares |
| `CCcam.providers` | Nomes dos provedores (`caid:provid:nome`) — mostrados no painel | ❌ Não — já vem com uma base curada |
| `CCcam.channelinfo` | Nomes dos canais (`caid:provid:sid:nome`) — o painel mostra o canal que cada cliente está a ver | ❌ Não — atualizar só quando os SIDs mudarem |

> **Dica**: quase tudo também pode ser editado pelo painel web
> (secção **Ficheiros**) — sem precisar de mexer por SSH.

## Como instalar (passo a passo)

### Com o instalador automático (recomendado)

```bash
curl -fsSL https://raw.githubusercontent.com/sharillas/CCcam-3.0.1-by-Sharillas/main/install.sh | bash
```

Instala o binário, o wrapper de controlo (`cccam3 start|stop|restart|status|log`)
e as configs em `/etc/cccam3/`, e cria o serviço.

### Manualmente

1. Cria a pasta onde o servidor vai ler os ficheiros:

```bash
sudo mkdir -p /etc/cccam3
```

2. Copia os ficheiros desta pasta para lá:

```bash
sudo cp configs/cccam3.conf        /etc/cccam3/cccam3.conf
sudo cp configs/cccam3.users       /etc/cccam3/cccam3.users
sudo cp configs/cccam3.readers     /etc/cccam3/cccam3.readers
sudo cp configs/SoftCam.Key        /etc/cccam3/SoftCam.Key
sudo cp configs/CCcam.providers    /etc/cccam3/CCcam.providers
sudo cp configs/CCcam.channelinfo  /etc/cccam3/CCcam.channelinfo
```

3. Edita o que precisares:

```bash
sudo nano /etc/cccam3/cccam3.conf
```

4. Arranca o servidor:

```bash
cccam3 restart
# ou manualmente:
cccam3 -c /etc/cccam3/cccam3.conf
```

## Conceitos essenciais (sem tecnicismos)

- **ECM** — é o "pedido" que o descodificador faz a cada ~5 segundos:
  "dá-me a chave deste canal". O servidor responde com a **CW** (a chave).
- **CW (Control Word)** — a chave que desbloqueia o canal durante alguns
  segundos. É isto que circula entre o servidor e os clientes.
- **Leitor** — a "fonte" de chaves. Pode ser:
  - **emu** — chaves no SoftCam.Key (sem cartão, sem outro servidor);
  - **remote** — outro servidor de share que tem os cartões;
  - **local** — um cartão real ligado por leitor PC/SC (Seca/Conax).
- **EMM** — mensagens que renovam os direitos dos cartões. O servidor
  reencaminha-as aos leitores remotos (e usa-as para atualizar chaves EMU).
- **Hop** — quantos servidores a chave já atravessou. O cartão original é
  hop 0; quem recebe de ti está a hop +1. Limites de hops protegem o
  cartão original.
- **Cache** — memória que guarda a última chave de cada canal: se o
  descodificador voltar a pedir o mesmo canal em poucos segundos, a
  resposta é imediata (zapping mais rápido).

## Cenários comuns (o que fazer em cada um)

1. **Só quero abrir canais BISS/feeds e Viaccess** (Abertis, TNTSAT...):
   - `cccam3.readers`: mantém só o leitor `[EMU_Reader]`.
   - `SoftCam.Key`: cola as chaves.
   - `cccam3.users`: adiciona os teus clientes.
2. **Quero partilhar o que recebo de outro servidor de share**:
   - `cccam3.readers`: configura o leitor `[Remote_Reader]` com o IP,
     porta, utilizador e password do outro servidor.
3. **Tenho uma box enigma2 e quero que ela descodifique sozinha**:
   - A box liga-se ao CCcam3 pela DVBAPI (socket `/tmp/camd.socket`);
   - `cccam3.conf` → `[dvbapi] enabled = 1`.
4. **Quero gerir tudo pelo navegador**:
   - Abre `http://IP-do-servidor:8080/web`
   - Põe utilizador/password em `[rest_api]` para ninguém espreitar.
   - No painel podes ver os clientes (com o canal que estão a ver e os
     ECM OK/NOK) e editar todos os ficheiros sem SSH.

## Sinais e comandos úteis

| Comando | O que faz |
|---|---|
| `cccam3 start` / `stop` / `restart` | Controla o serviço (de qualquer pasta) |
| `cccam3 status` | Estado do serviço |
| `cccam3 log` | Vê o log em tempo real |
| `kill -HUP $(cat /var/run/cccam3.pid)` | Recarrega o SoftCam.Key sem reiniciar |
| `kill -USR1 $(cat /var/run/cccam3.pid)` | Roda o ficheiro de log |
| `cccam3 -c /etc/cccam3/cccam3.conf -d` | Corre em segundo plano (daemon) |
| `cccam3 -t` | Testa o servidor (self-tests) |

# Changelog

## 3.0.2 (em desenvolvimento)

### Segurança
- RC4 com keystream contínua por sessão/direção (fim da reutilização)
- AES/3DES passaram de ECB para **CBC com IV derivado por mensagem**
- AES-GCM como modo por omissão (inclusive no handshake legado, com
  chave derivada por SHA256)
- Refcount no pool de clientes: fim do use-after-free entre o loop
  principal e as threads de ECM/REST
- `fchmod 0600` em ficheiros sensíveis (users, SoftCam.Key)
- Validação da config com clamps e avisos

### Robustez
- **Thread por cliente**: um cliente lento já não bloqueia os restantes
- REST API com thread pool limitada (anti-DoS) + `/healthz` e `/metrics`
- `SIGHUP` recarrega chaves, utilizadores, leitores e canais
- Mutexes no user manager com reload copy-swap
- DVB: zapping em runtime (`/dvb/zap?sid=`), autoscan de adaptadores

### Compatibilidade
- **Clientes CCcam comerciais 2.0.11–2.1.4 (Fase 1)**: login clássico,
  cifra CCcrypt, pedidos ECM e respostas CW no protocolo binário real
  (portado do OSCam, GPLv3)

### Infraestrutura
- CI: jobs de sanitizers (ASan/UBSan), build `-Werror` e fuzzing do parser
- `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`

## 3.0.1

- Servidor funcional de ponta a ponta (login, handshake, ECMs, cache LRU)
- Newcamd real, DVBAPI ca_pmt, leitores remotos TCP, leitor DVB direto
- EMU real (Viaccess/BISS/Cryptoworks/PowerVU/Nagra2/Irdeto2)
- Smartcard local via PC/SC
- Binários estáticos multi-arquitetura + pacote IPK para enigma2
- Auditoria de segurança (19 correções)

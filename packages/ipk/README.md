# Pacote IPK do CCcam3 (enigma2)

Estrutura usada pela GitHub Action para gerar o pacote
`enigma2-plugin-softcams-cccam3_3.0.1_all.ipk`, instalável em
OpenPLi / OpenATV / OpenViX (OE 1.6/2.0 ou superior) com:

```
opkg install --force-overwrite /tmp/enigma2-plugin-softcams-cccam3_3.0.1_all.ipk
```

## Conteúdo do pacote

| Caminho no pacote | Descrição |
|---|---|
| `CONTROL/control` | Metadados opkg (nome, versão, arch `all`) |
| `CONTROL/postinst` | Pós-instalação: escolhe o binário certo para a arquitetura, cria as configs em `/etc/cccam3/` (se não existirem), ajusta o log para `/var/volatile/log` (tmpfs, preserva a flash) e inicia o serviço |
| `CONTROL/prerm` | Para o serviço antes de remover/atualizar |
| `etc/init.d/cccam3` | Script de arranque SysVinit: `start|stop|restart|status` |
| `usr/lib/enigma2/python/Plugins/Extensions/CCcam3/plugin.py` | Entrada no menu da box: **Menu > Plugins > CCcam3** (iniciar/parar/estado) |
| `usr/share/cccam3/*` | Configurações de exemplo (copiadas para `/etc/cccam3/` no postinst, sem sobrescrever) |
| `usr/bin/cccam3-<arch>` | Os 6 binários estáticos (o postinst copia o certo para `/usr/bin/cccam3`) |

## Geração

A GitHub Action `.github/workflows/build-release.yml` monta o `.ipk`
(formato `ar` + `control.tar.gz` + `data.tar.gz`) depois de compilar os
6 binários estáticos e anexa-o à release.

Para gerar manualmente num Linux:

```bash
./packages/ipk/make_ipk.sh   # se disponível
```

## Notas

- Binários **totalmente estáticos** (libc incluída) — correm em qualquer
  imagem OE (glibc antigo, uClibc ou musl)
- Nos readers remotos usar sempre **IP** (binários estáticos não fazem
  resolução de hostnames em algumas boxes)
- Painel web: http://IP-da-box:8080/web

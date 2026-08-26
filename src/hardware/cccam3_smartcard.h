#ifndef CCCAM3_SMARTCARD_H
#define CCCAM3_SMARTCARD_H

#include <stdint.h>
#include <stddef.h>

// --- Leitor local de smartcards via PC/SC (libpcsclite) ---
// Compilar com -DUSE_PCSC e ligar -lpcsclite para ativar.
// Sem PC/SC as funções devolvem erro (sem dados simulados).

// Inicializa o contexto PC/SC
int cccam_smartcard_init(void);

// Limpa o contexto PC/SC
void cccam_smartcard_cleanup(void);

// Devolve 1 se o suporte a PC/SC está compilado e inicializado
int cccam_smartcard_available(void);

// Envia um ECM ao cartão e obtém a CW (16 bytes).
// reader_name: nome do leitor PC/SC ("" ou NULL = primeiro leitor disponível).
// Suportado: Seca/Mediaguard (0x0100) e Conax (0x0B00).
// Devolve 0 em caso de sucesso, -1 em caso de erro.
int cccam_smartcard_ecm(const char *reader_name, uint16_t caid, uint16_t provid,
                        const uint8_t *ecm, uint16_t ecm_len, uint8_t *cw);

#endif // CCCAM3_SMARTCARD_H

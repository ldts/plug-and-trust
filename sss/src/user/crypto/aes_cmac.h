#ifndef __AES_CMAC_H
#define __AES_CMAC_H

void aes_cmac(uint8_t *input, size_t length, uint8_t *key, uint8_t *mac);

void aes_cmac_update(struct aes_ctx *context, uint8_t *input, uint8_t *iv,
		     size_t length, uint8_t *key, uint8_t *mac);

void aes_cmac_finish(struct aes_ctx *context, uint8_t *input, uint8_t *iv,
		     size_t length, uint8_t *key, uint8_t *mac);
#endif

/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef GLUE_H
#define GLUE_H

#include <fsl_sss_api.h>

int glue_i2c_read(uint8_t *buffer, int len);
int glue_i2c_write(uint8_t *buffer, int len);
int glue_i2c_init(void);

sss_status_t glue_mac_context_init(void **mac, const uint8_t *key, size_t len);
void glue_mac_context_free(void *mac);
sss_status_t glue_mac_update(void *mac, const uint8_t *msg, size_t len);
sss_status_t glue_mac_final(void *mac, uint8_t *buf, size_t len);
sss_status_t glue_mac_one_go(void *mac, const uint8_t *msg, size_t msg_len,
			     uint8_t *buf, size_t mac_len);
sss_status_t glue_symmetric_context_init(void **cipher);
sss_status_t glue_cipher_one_go(void *cipher, TEE_OperationMode mode,
				uint8_t *iv, size_t iv_len,
				uint8_t *key, size_t key_len,
				const uint8_t *src, uint8_t *dst, size_t len);
void glue_context_free(void *cipher);
sss_status_t glue_rng_get_random(uint8_t *data __unused, size_t len __unused);
#endif /* GLUE_H */

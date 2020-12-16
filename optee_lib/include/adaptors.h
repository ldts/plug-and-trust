/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef ADAPTORS_H
#define ADAPTORS_H

#include <der.h>
#include <fsl_sss_api.h>
void add_ecc_header(uint8_t *k, uint8_t **p, size_t *len, uint32_t id);
void get_ecc_raw_data(uint8_t *key, uint8_t **key_buf, size_t *key_buflen, uint32_t curve_id);

#endif /* ADAPTORS_H */

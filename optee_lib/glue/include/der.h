/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#ifndef DER_H
#define DER_H

#include <fsl_sss_api.h>

/* bytes needed to encode a DER signature rounded to power of 2 */
#define DER_SIGNATURE_SZ		8

void sss_se05x_signature_der2bin(uint8_t *sig, size_t *sig_len);
sss_status_t sss_se05x_signature_bin2der(uint8_t *sig, size_t *sig_len,
					 const uint8_t *raw, size_t raw_len);

#endif /* DER_H */

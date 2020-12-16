// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <der.h>
#include <string.h>

void sss_se05x_signature_der2bin(uint8_t *p, size_t *p_len)
{
	uint8_t buffer[256] = { };
	size_t buffer_len = 0;
	uint8_t	*output = p;
	uint8_t *k = NULL;
	size_t len = 0;

	if (!p || !p_len)
		return;

	p++;            /* tag: 0x30 */
	p++;            /* field: total len */
	p++;            /* tag: 0x02 */
	len = *p++;     /* field: r_len */

	if (*p == 0x00) { /* handle special case */
		len = len - 1;
		p++;
	}
	memcpy(buffer, p, len);

	p = p + len;
	p++;            /* tag: 0x2 */
	k = p;
	p++;            /* field: s_len */

	if (*p == 0x00) {
		*k = *k - 1;
		p++;
	}
	memcpy(buffer + len, p, *k);
	buffer_len = len + *k;

	memcpy(output, buffer, buffer_len);
	*p_len = buffer_len;
}

sss_status_t sss_se05x_signature_bin2der(uint8_t *signature,
					 size_t *signature_len,
					 const uint8_t *raw, size_t raw_len)
{
	size_t der_len =  6 + raw_len;
	size_t r_len = raw_len / 2;
	size_t s_len = raw_len / 2;

	if (*signature_len < der_len)
		return kStatus_SSS_Fail;

	if (raw_len != 48 && raw_len != 56 && raw_len != 64 && raw_len != 96)
		return kStatus_SSS_Fail;

	*signature_len = der_len;

	signature[0] = 0x30;
	signature[1] = (uint8_t)(raw_len + 4);
	signature[2] = 0x02;
	signature[3] = (uint8_t)r_len;
	memcpy(&signature[4], &raw[0], r_len);

	signature[3 + r_len + 1] = 0x02;
	signature[3 + r_len + 2] = (uint8_t)s_len;
	memcpy(&signature[3 + r_len + 3], &raw[r_len], s_len);

	return kStatus_SSS_Success;
}

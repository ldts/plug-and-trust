// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright (C) Foundries Ltd. 2020 - All Rights Reserved
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <phEseStatus.h>
#include <phNxpEsePal_i2c.h>

extern int glue_i2c_read(uint8_t *buffer, int len);
extern int glue_i2c_write(uint8_t *buffer, int len);
extern int glue_i2c_init(void);

void phPalEse_i2c_close(void *handle)
{
}

int phPalEse_i2c_read(void *foo, uint8_t *buffer, int len)
{
	return glue_i2c_read(buffer, len);
}

int phPalEse_i2c_write(void *foo, uint8_t *buffer, int len)
{
	return glue_i2c_write(buffer, len);
}

ESESTATUS phPalEse_i2c_open_and_configure(pphPalEse_Config_t pConfig)
{
	if (glue_i2c_init())
		return ESESTATUS_INVALID_DEVICE;

	return ESESTATUS_SUCCESS;
}

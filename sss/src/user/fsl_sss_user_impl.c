#include "crypto/aes.h"
#include "crypto/aes_cmac.h"
#include "fsl_sss_ftr.h"
#include "fsl_sss_user_apis.h"
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAC_BLOCK_SIZE 16

#define ENSURE_OR_EXIT(condition)	\
	if (!(condition)) {		\
		goto exit;		\
	}

sss_status_t sss_user_impl_rng_context_init(sss_user_impl_rng_context_t *c,
					    sss_user_impl_session_t *session)
{
	srand(time(NULL));

	return kStatus_SSS_Success;
}

sss_status_t sss_user_impl_rng_get_random(sss_user_impl_rng_context_t *context,
					  uint8_t *data, size_t len)
{
	sss_status_t status = kStatus_SSS_Fail;
	size_t i;

	ENSURE_OR_EXIT(context);
	for (i = 0; i < len; i++)
		data[i] = (uint8_t)rand();

	status = kStatus_SSS_Success;
exit:
	return status;
}

sss_status_t sss_user_impl_session_open(sss_user_impl_session_t *s,
					sss_type_t subsystem,
					uint32_t application_id __unused,
					sss_connection_type_t type,
					void *data __unused)
{
	sss_status_t ret = kStatus_SSS_Fail;

	ENSURE_OR_EXIT(s != NULL);
	ENSURE_OR_EXIT(type == kSSS_ConnectionType_Plain);

	memset(s, 0, sizeof(*s));

	s->subsystem = subsystem;
	ret = kStatus_SSS_Success;
exit:
	return ret;
}

sss_status_t sss_user_impl_key_object_init(sss_user_impl_object_t *key,
					   sss_user_impl_key_store_t *store)
{
	sss_status_t ret = kStatus_SSS_Fail;

	ENSURE_OR_EXIT(key);
	ENSURE_OR_EXIT(store);

	memset(key, 0, sizeof(*key));
	key->keyStore = store;
	ret = kStatus_SSS_Success;
exit:
	return ret;
}

sss_status_t sss_user_impl_key_object_allocate_handle(sss_user_impl_object_t
						      *key,
						      uint32_t key_id,
						      sss_key_part_t key_part,
						      sss_cipher_type_t type,
						      size_t len,
						      uint32_t options)
{
	sss_status_t ret = kStatus_SSS_Fail;

	ENSURE_OR_EXIT(key);
	ENSURE_OR_EXIT(key_id != 0);
	ENSURE_OR_EXIT(key_id != 0xFFFFFFFFu);

	if (options != kKeyObject_Mode_Persistent &&
	    options != kKeyObject_Mode_Transient) {
		ret = kStatus_SSS_Fail;
		goto exit;
	}

	if (key_part > UINT8_MAX) {
		ret = kStatus_SSS_Fail;
		goto exit;
	}

	if (len) {
		key->contents = malloc(len);
		ENSURE_OR_EXIT(key->contents);

		memset(key->contents, 0, len);
		key->contents_size = len;
		ret = kStatus_SSS_Success;
	}
exit:
	return ret;
}

sss_status_t sss_user_impl_key_store_context_init(sss_user_impl_key_store_t
						  *store,
						  sss_user_impl_session_t *s)
{
	sss_status_t ret = kStatus_SSS_Fail;

	ENSURE_OR_EXIT(store);
	ENSURE_OR_EXIT(s);

	memset(store, 0, sizeof(*store));
	store->session = s;
	ret = kStatus_SSS_Success;
exit:
	return ret;
}

sss_status_t sss_user_impl_key_store_allocate(sss_user_impl_key_store_t *store,
					      uint32_t id __unused)
{
	sss_status_t ret = kStatus_SSS_Fail;

	ENSURE_OR_EXIT(store);
	ENSURE_OR_EXIT(store->session);
	ret = kStatus_SSS_Success;
exit:
	return ret;
}

sss_status_t sss_user_impl_key_store_set_key(sss_user_impl_key_store_t *store,
					     sss_user_impl_object_t *key,
					     const uint8_t *data,
					     size_t data_len,
					     size_t key_len __unused,
					     void *options __unused,
					     size_t options_len __unused)
{
	sss_status_t ret = kStatus_SSS_Fail;

	ENSURE_OR_EXIT(data != NULL);
	ENSURE_OR_EXIT(key != NULL);
	ENSURE_OR_EXIT(data_len <= key->contents_size);

	memcpy(key->key, data, data_len);
	key->contents_size = data_len;

	ret = kStatus_SSS_Success;
exit:
	return ret;
}

sss_status_t sss_user_impl_cipher_one_go(sss_user_impl_symmetric_t *context,
					 uint8_t *iv, size_t iv_len,
					 const uint8_t *src, uint8_t *dst,
					 size_t data_len)
{
	sss_status_t ret = kStatus_SSS_Fail;
	uint8_t indata[AES_BLOCKSIZE] = { 0 };
	size_t i = 0;

	ENSURE_OR_EXIT(context);
	ENSURE_OR_EXIT(iv);
	ENSURE_OR_EXIT(src);
	ENSURE_OR_EXIT(dst);
	ENSURE_OR_EXIT(data_len % AES_BLOCKSIZE == 0);

	if (context->mode == kMode_SSS_Encrypt) {
		while (data_len > 0) {
			memcpy(indata, src, AES_BLOCKSIZE);

			for (i = 0; i < AES_BLOCKSIZE; i++)
				indata[i] ^= iv[i];

			AES_encrypt(context->pAesctx, indata, dst);
			memcpy(iv, dst, AES_BLOCKSIZE);

			src += AES_BLOCKSIZE;
			dst += AES_BLOCKSIZE;
			data_len -= AES_BLOCKSIZE;
		}
		return kStatus_SSS_Success;
	}

	if (context->mode == kMode_SSS_Decrypt) {
		while (data_len > 0) {
			memcpy(indata, src, AES_BLOCKSIZE);

			AES_decrypt(context->pAesctx, indata, dst);
			for (i = 0; i < AES_BLOCKSIZE; i++)
				dst[i] ^= iv[i];
			memcpy(iv, indata, AES_BLOCKSIZE);

			src += AES_BLOCKSIZE;
			dst += AES_BLOCKSIZE;
			data_len -= AES_BLOCKSIZE;
		}
		return kStatus_SSS_Success;
	}
exit:
	return ret;
}

sss_status_t sss_user_impl_mac_context_init(sss_user_impl_mac_t *context,
					    sss_user_impl_session_t *session,
					    sss_user_impl_object_t *keyObject,
					    sss_algorithm_t algorithm,
					    sss_mode_t mode)
{
	sss_status_t ret = kStatus_SSS_Fail;

	SSS_ASSERT(sizeof(sss_user_impl_mac_t) < sizeof(sss_mac_t));
	ENSURE_OR_EXIT(context);
	ENSURE_OR_EXIT(keyObject);

	memset(context, 0, sizeof(*context));
	context->keyObject = keyObject;
	context->pAesmacctx = AES_ctx_alloc(keyObject->key,
					    sizeof(keyObject->key));
	ENSURE_OR_EXIT(context->pAesmacctx);

	ret = kStatus_SSS_Success;
exit:
	return ret;
}
sss_status_t sss_user_impl_mac_init(sss_user_impl_mac_t *context)
{
	sss_status_t ret = kStatus_SSS_Fail;

	ENSURE_OR_EXIT(context);
	memset(context->calc_mac, 0, sizeof(*context->calc_mac));
	memset(context->cache_data, 0, sizeof(*context->cache_data));
	context->cache_dataLen = 0;

	ret = kStatus_SSS_Success;
exit:
	return ret;
}

sss_status_t sss_user_impl_mac_update(sss_user_impl_mac_t *context,
				      const uint8_t *msg, size_t msg_len)
{
	sss_status_t status = kStatus_SSS_Fail;
	uint8_t input[MAC_BLOCK_SIZE] = { 0 };
	uint8_t mac[MAC_BLOCK_SIZE] = { 0 };
	size_t n = 0, i = 0;

	ENSURE_OR_EXIT(context);
	SSS_ASSERT(sizeof(sss_user_impl_mac_t) < sizeof(sss_mac_t));

	if (context->cache_dataLen > 0 &&
	    msg_len > (MAC_BLOCK_SIZE - context->cache_dataLen)) {

		memcpy(&context->cache_data[context->cache_dataLen], msg,
		       MAC_BLOCK_SIZE - context->cache_dataLen);

		aes_cmac_update(context->pAesmacctx, context->cache_data,
				context->calc_mac, MAC_BLOCK_SIZE,
				context->keyObject->key, mac);

		memcpy(context->calc_mac, mac, MAC_BLOCK_SIZE);

		msg += MAC_BLOCK_SIZE - context->cache_dataLen;
		msg_len -= MAC_BLOCK_SIZE - context->cache_dataLen;
		context->cache_dataLen = 0;
	}

	n = (msg_len + MAC_BLOCK_SIZE - 1) / MAC_BLOCK_SIZE;

	for (i = 1; i < n; i++) {
		memcpy(input, msg, MAC_BLOCK_SIZE);
		aes_cmac_update(context->pAesmacctx, input, context->calc_mac,
				MAC_BLOCK_SIZE, context->keyObject->key, mac);
		memcpy(context->calc_mac, mac, MAC_BLOCK_SIZE);
		msg_len -= MAC_BLOCK_SIZE;
		msg += MAC_BLOCK_SIZE;
	}

	if (msg_len) {
		memcpy(context->cache_data, msg, msg_len);
		context->cache_dataLen += msg_len;
	}

	status = kStatus_SSS_Success;
exit:
	return status;
}

sss_status_t sss_user_impl_mac_finish(sss_user_impl_mac_t *context,
				      uint8_t *mac, size_t *len)
{
	sss_status_t status = kStatus_SSS_Fail;
	uint8_t input[MAC_BLOCK_SIZE] = { 0 };
	size_t inputLen = 0;

	ENSURE_OR_EXIT(context);
	ENSURE_OR_EXIT(mac);
	ENSURE_OR_EXIT(len);

	memcpy(input, context->cache_data, context->cache_dataLen);
	inputLen = context->cache_dataLen;

	aes_cmac_finish(context->pAesmacctx, input, context->calc_mac, inputLen,
			context->keyObject->key, mac);

	*len = MAC_BLOCK_SIZE;
	status  = kStatus_SSS_Success;
exit:
	return status;
}

sss_status_t sss_user_impl_mac_one_go(sss_user_impl_mac_t *context,
				      const uint8_t *msg, size_t msg_len,
				      uint8_t *mac, size_t *mac_len)
{
	sss_status_t status = kStatus_SSS_Fail;
	uint8_t input[1024] = { 0 };

	ENSURE_OR_EXIT(context);

	memcpy(input, msg, msg_len);
	aes_cmac(input, msg_len, context->keyObject->key, mac);
	*mac_len = AES_BLOCKSIZE;

	status = kStatus_SSS_Success;
exit:
	return status;
}

void sss_user_impl_mac_context_free(sss_user_impl_mac_t *context)
{
	if (!context)
		return;

	if (context->pAesmacctx) {
		memset(context->pAesmacctx, 3, sizeof(*context->pAesmacctx));
		free(context->pAesmacctx);
	}

	memset(context->calc_mac, 0, MAC_BLOCK_SIZE);
	memset(context->cache_data, 0, MAC_BLOCK_SIZE);
}

void sss_user_impl_symmetric_context_free(sss_user_impl_symmetric_t *context)
{
	if (!context->pAesctx)
		return;

	free(context->pAesctx);
	context->pAesctx = NULL;
}

sss_status_t sss_user_impl_symmetric_context_init(sss_user_impl_symmetric_t *c,
						  sss_user_impl_session_t *s,
						  sss_user_impl_object_t *key,
						  sss_algorithm_t algorithm,
						  sss_mode_t mode)
{
	sss_status_t status = kStatus_SSS_Fail;

	ENSURE_OR_EXIT(c);
	ENSURE_OR_EXIT(s);
	ENSURE_OR_EXIT(key);
	SSS_ASSERT(sizeof(sss_user_impl_symmetric_t) <=
		   sizeof(sss_symmetric_t));

	c->session = s;
	c->keyObject = key;
	c->algorithm = algorithm;
	c->mode = mode;

	c->pAesctx = AES_ctx_alloc(key->key, sizeof(key->key));
	ENSURE_OR_EXIT(c->pAesctx);

	status = kStatus_SSS_Success;
exit:
	return status;
}

void sss_user_impl_key_object_free(sss_user_impl_object_t *p)
{
	if (!p)
		return;

	if (p->contents) {
		free(p->contents);
		p->contents = NULL;
		p->contents_size = 0;
	}

	memset(p, 0, sizeof(*p));
}

void sss_user_impl_key_store_context_free(sss_user_impl_key_store_t *store)
{
	if (store)
		memset(store, 0, sizeof(*store));
}

void sss_user_impl_session_close(sss_user_impl_session_t *session)
{
	if (session)
		memset(session, 0, sizeof(*session));
}

sss_status_t sss_user_impl_derive_key_context_init(sss_user_impl_derive_key_t
						   *context,
						   sss_user_impl_session_t *s,
						   sss_user_impl_object_t *k,
						   sss_algorithm_t algorithm,
						   sss_mode_t mode)
{
	return kStatus_SSS_Fail;
}

sss_status_t sss_user_impl_derive_key_go(sss_user_impl_derive_key_t *context,
					 const uint8_t *saltData,
					 size_t saltLen, const uint8_t *info,
					 size_t infoLen,
					 sss_user_impl_object_t *p,
					 uint16_t d, uint8_t *h, size_t *h_len)
{
	return kStatus_SSS_Fail;
}

sss_status_t sss_user_impl_derive_key_dh(sss_user_impl_derive_key_t *context,
					 sss_user_impl_object_t *p,
					 sss_user_impl_object_t *q)
{
	return kStatus_SSS_Fail;
}

void sss_user_impl_derive_key_context_free(sss_user_impl_derive_key_t *context)
{
}

sss_status_t sss_user_impl_asymmetric_context_init(sss_user_impl_asymmetric_t
						   *context,
						   sss_user_impl_session_t *s,
						   sss_user_impl_object_t *k,
						   sss_algorithm_t algorithm,
						   sss_mode_t mode)
{
	return kStatus_SSS_Fail;
}

sss_status_t sss_user_impl_asymmetric_sign_digest(sss_user_impl_asymmetric_t *c,
						  uint8_t *dgst,
						  size_t dgst_Len,
						  uint8_t *sig, size_t *sig_len)
{
	return kStatus_SSS_Fail;
}

void sss_user_impl_asymmetric_context_free(sss_user_impl_asymmetric_t *context)
{
}

sss_status_t sss_user_impl_digest_context_init(sss_user_impl_digest_t *context,
					       sss_user_impl_session_t *session,
					       sss_algorithm_t algorithm,
					       sss_mode_t mode)
{
	return kStatus_SSS_Fail;
}

sss_status_t sss_user_impl_digest_one_go(sss_user_impl_digest_t *context,
					 const uint8_t *m, size_t m_len,
					 uint8_t *d, size_t *d_len)
{
	return kStatus_SSS_Fail;
}

void sss_user_impl_digest_context_free(sss_user_impl_digest_t *context)
{
}

sss_status_t sss_user_impl_key_store_get_key(sss_user_impl_key_store_t *Store,
					     sss_user_impl_object_t *key,
					     uint8_t *data,
					     size_t *dataLen,
					     size_t *pKeyBitLen)
{
	return kStatus_SSS_Success;
}

sss_status_t sss_user_impl_key_store_generate_key(sss_user_impl_key_store_t *s,
						  sss_user_impl_object_t *k,
						  size_t len,
						  void *options)
{
	return kStatus_SSS_Fail;
}

sss_status_t sss_user_impl_rng_context_free(sss_user_impl_rng_context_t *context)
{
	return kStatus_SSS_Success;
}


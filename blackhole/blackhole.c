/*-------------------------------------------------------------------------
 *
 * blackhole.c
 *		Set of functions for a minimal extension template
 *
 * Copyright (c) 1996-2020, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *		  blackhole/blackhole.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include "fmgr.h"

#include "common/hmac.h"
#include "common/md5.h"
#include "common/sha2.h"

PG_MODULE_MAGIC;

/*
 * This is the blackhole function.
 */
PG_FUNCTION_INFO_V1(hmac_md5);
PG_FUNCTION_INFO_V1(hmac_sha256);

Datum
hmac_md5(PG_FUNCTION_ARGS)
{
	bytea      *arg = PG_GETARG_BYTEA_PP(0);
	bytea      *key = PG_GETARG_BYTEA_PP(1);
	const uint8 *data;
	const uint8 *keydata;
	size_t      len, keylen;
	pg_hmac_ctx *ctx;
	unsigned char buf[MD5_DIGEST_LENGTH];
	bytea      *result;

	len = VARSIZE_ANY_EXHDR(arg);
	data = (unsigned char *) VARDATA_ANY(arg);
	keylen = VARSIZE_ANY_EXHDR(key);
	keydata = (unsigned char *) VARDATA_ANY(key);

	ctx = pg_hmac_create(PG_MD5);
	if (pg_hmac_init(ctx, keydata, keylen) < 0)
		elog(ERROR, "could not initialize %s context", "MD5");
	if (pg_hmac_update(ctx, data, len) < 0)
		elog(ERROR, "could not update %s context", "MD5");
	if (pg_hmac_final(ctx, buf) < 0)
		elog(ERROR, "could not finalize %s context", "MD5");
	pg_hmac_free(ctx);

	result = palloc(sizeof(buf) + VARHDRSZ);
	SET_VARSIZE(result, sizeof(buf) + VARHDRSZ);
	memcpy(VARDATA(result), buf, sizeof(buf));

	PG_RETURN_BYTEA_P(result);
}

Datum
hmac_sha256(PG_FUNCTION_ARGS)
{
	bytea      *arg = PG_GETARG_BYTEA_PP(0);
	bytea      *key = PG_GETARG_BYTEA_PP(1);
	const uint8 *data;
	const uint8 *keydata;
	size_t      len, keylen;
	pg_hmac_ctx *ctx;
	unsigned char buf[PG_SHA256_DIGEST_LENGTH];
	bytea      *result;

	len = VARSIZE_ANY_EXHDR(arg);
	data = (unsigned char *) VARDATA_ANY(arg);
	keylen = VARSIZE_ANY_EXHDR(key);
	keydata = (unsigned char *) VARDATA_ANY(key);

	ctx = pg_hmac_create(PG_SHA256);
	if (pg_hmac_init(ctx, keydata, keylen) < 0)
		elog(ERROR, "could not initialize %s context", "SHA256");
	if (pg_hmac_update(ctx, data, len) < 0)
		elog(ERROR, "could not update %s context", "SHA256");
	if (pg_hmac_final(ctx, buf) < 0)
		elog(ERROR, "could not finalize %s context", "SHA256");
	pg_hmac_free(ctx);

	result = palloc(sizeof(buf) + VARHDRSZ);
	SET_VARSIZE(result, sizeof(buf) + VARHDRSZ);
	memcpy(VARDATA(result), buf, sizeof(buf));

	PG_RETURN_BYTEA_P(result);
}

/*
 * Copyright 2022-2023 Huawei Technologies Co.,Ltd. All rights reserved.
 * Copyright 2022-2023 Linaro ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>

#include "uadk.h"

struct p_uadk_ctx {
	const OSSL_CORE_HANDLE *handle;
	OSSL_LIB_CTX *libctx;
};

static const char UADK_DEFAULT_PROPERTIES[] = "provider=uadk";

const OSSL_ALGORITHM uadk_prov_digests[] = {
	{ OSSL_DIGEST_NAME_MD5, UADK_DEFAULT_PROPERTIES, uadk_md5_functions },
	{ OSSL_DIGEST_NAME_SM3, UADK_DEFAULT_PROPERTIES, uadk_sm3_functions },
	{ OSSL_DIGEST_NAME_SHA1, UADK_DEFAULT_PROPERTIES, uadk_sha1_functions },
	{ OSSL_DIGEST_NAME_SHA3_224, UADK_DEFAULT_PROPERTIES, uadk_sha3_224_functions },
	{ OSSL_DIGEST_NAME_SHA3_256, UADK_DEFAULT_PROPERTIES, uadk_sha3_256_functions },
	{ OSSL_DIGEST_NAME_SHA3_384, UADK_DEFAULT_PROPERTIES, uadk_sha3_384_functions },
	{ OSSL_DIGEST_NAME_SHA3_512, UADK_DEFAULT_PROPERTIES, uadk_sha3_512_functions },
	{ NULL, NULL, NULL }
};


static OSSL_FUNC_provider_query_operation_fn p_prov_query;
static OSSL_FUNC_provider_teardown_fn p_teardown;

static const OSSL_ALGORITHM *p_prov_query(void *provctx, int operation_id,
					  int *no_cache)
{
	*no_cache = 0;
	switch (operation_id) {
	case OSSL_OP_DIGEST:
		return uadk_prov_digests;
	}
	return NULL;
}

static const OSSL_DISPATCH p_test_table[] = {
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))p_prov_query },
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))p_teardown },
	{ 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
		       const OSSL_DISPATCH *oin,
		       const OSSL_DISPATCH **out,
		       void **provctx)
{
	struct p_uadk_ctx *ctx;
	const OSSL_DISPATCH *in = oin;

	for (; in->function_id != 0; in++) {
		switch (in->function_id) {
		}
	}

	ctx = OPENSSL_zalloc(sizeof(*ctx));
	if (ctx == NULL)
		return 0;

	*provctx = (void *)ctx;
	*out = p_test_table;
	return 1;
}

static void p_teardown(void *provctx)
{
	struct p_uadk_ctx *ctx = (struct p_uadk_ctx *)provctx;

	OPENSSL_free(ctx);

}


#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>

typedef struct{
    int id; /* libcrypto internal */
    int name_id;
    char *type_name;
    const char *description;
    OSSL_PROVIDER *prov;

    int refcnt;
    void *lock;

    /* Constructor(s), destructor, information */
    OSSL_FUNC_keymgmt_new_fn *new;
    OSSL_FUNC_keymgmt_free_fn *free;
    OSSL_FUNC_keymgmt_get_params_fn *get_params;
    OSSL_FUNC_keymgmt_gettable_params_fn *gettable_params;
    OSSL_FUNC_keymgmt_set_params_fn *set_params;
    OSSL_FUNC_keymgmt_settable_params_fn *settable_params;

    /* Generation, a complex constructor */
    OSSL_FUNC_keymgmt_gen_init_fn *gen_init;
    OSSL_FUNC_keymgmt_gen_set_template_fn *gen_set_template;
    OSSL_FUNC_keymgmt_gen_set_params_fn *gen_set_params;
    OSSL_FUNC_keymgmt_gen_settable_params_fn *gen_settable_params;
    OSSL_FUNC_keymgmt_gen_fn *gen;
    OSSL_FUNC_keymgmt_gen_cleanup_fn *gen_cleanup;
    OSSL_FUNC_keymgmt_load_fn *load;

    /* Key object checking */
    OSSL_FUNC_keymgmt_query_operation_name_fn *query_operation_name;
    OSSL_FUNC_keymgmt_has_fn *has;
    OSSL_FUNC_keymgmt_validate_fn *validate;
    OSSL_FUNC_keymgmt_match_fn *match;

    /* Import and export routines */
    OSSL_FUNC_keymgmt_import_fn *import;
    OSSL_FUNC_keymgmt_import_types_fn *import_types;
    OSSL_FUNC_keymgmt_export_fn *export;
    OSSL_FUNC_keymgmt_export_types_fn *export_types;
    OSSL_FUNC_keymgmt_dup_fn *dup;

} UADK_RSA_KEYMGMT;


UADK_RSA_KEYMGMT get_default_keymgmt()
{
    static UADK_RSA_KEYMGMT s_keymgmt;
    static int initialized = 0;
    if (!initialized) {
        UADK_RSA_KEYMGMT *keymgmt = (UADK_RSA_KEYMGMT *)EVP_KEYMGMT_fetch(NULL, "RSA", "provider=default");
        if (keymgmt) {
            s_keymgmt = *keymgmt;
            EVP_KEYMGMT_free((EVP_KEYMGMT *)keymgmt);
            initialized = 1;
        } else {
            fprintf(stderr, "EVP_KEYMGMT_fetch from default provider failed");
        }
    }
    return s_keymgmt;
}

static void *uadk_keymgmt_rsa_newdata(void *provctx)
{
    typedef void* (*fun_ptr)(void *);
    fun_ptr fun = get_default_keymgmt().new;
    if (!fun)
        return NULL;
	printf("gzf %s\n", __func__);
    return fun(provctx);
}

static void uadk_keymgmt_rsa_freedata(void *keydata)
{
    typedef void (*fun_ptr)(void *);
    fun_ptr fun = get_default_keymgmt().free;
    if (!fun)
        return;
	printf("gzf %s\n", __func__);
    fun(keydata);
}

static int uadk_keymgmt_rsa_has(const void *keydata, int selection)
{
    typedef int (*fun_ptr)(const void *,int);
    fun_ptr fun = get_default_keymgmt().has;
    if (!fun)
        return 0;

	printf("gzf %s\n", __func__);
    return fun(keydata,selection);
}

static int uadk_keymgmt_rsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *, int, const OSSL_PARAM*);
    fun_ptr fun = get_default_keymgmt().import;
    if (!fun)
        return 0;
	printf("gzf %s\n", __func__);
    return fun(keydata,selection,params);
}

static const OSSL_PARAM *uadk_keymgmt_rsa_import_types(int selection)
{
    typedef const OSSL_PARAM* (*fun_ptr)(int);
    fun_ptr fun = get_default_keymgmt().import_types;
    if (!fun)
        return NULL;
	printf("gzf %s\n", __func__);
    return fun(selection);
}

static void *uadk_keymgmt_rsa_gen_init(void *provctx, int selection,
                          const OSSL_PARAM params[])
{
    typedef void * (*fun_ptr)(void *, int, const OSSL_PARAM *);
    fun_ptr fun = get_default_keymgmt().gen_init;
    if (!fun)
        return NULL;
	printf("gzf %s\n", __func__);
    return fun(provctx, selection, params);
}

static int uadk_keymgmt_rsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *, const OSSL_PARAM *);
    fun_ptr fun = get_default_keymgmt().gen_set_params;
    if (!fun)
        return 0;
    return fun(genctx, params);
}

static const OSSL_PARAM *uadk_keymgmt_rsa_gen_settable_params(ossl_unused void *genctx,
                                                 ossl_unused void *provctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *, void *);
    fun_ptr fun = get_default_keymgmt().gen_settable_params;
    if (!fun)
        return NULL;
    return fun(genctx, provctx);
}

static void *uadk_keymgmt_rsa_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    typedef void * (*fun_ptr)(void *, OSSL_CALLBACK *, void *);
    fun_ptr fun = get_default_keymgmt().gen;
    if (!fun)
        return NULL;
	printf("gzf %s\n", __func__);
    return fun(genctx, osslcb, cbarg);
}

static void uadk_keymgmt_rsa_gen_cleanup(void *genctx)
{
    typedef void (*fun_ptr)(void *);
    fun_ptr fun = get_default_keymgmt().gen_cleanup;
    if (!fun)
        return;
	printf("gzf %s\n", __func__);
    fun(genctx);
}

static void *uadk_keymgmt_rsa_load(const void *reference, size_t reference_sz)
{
    typedef void * (*fun_ptr)(const void *, size_t);
    fun_ptr fun = get_default_keymgmt().load;
    if (!fun)
        return NULL;
	printf("gzf %s\n", __func__);
    return fun(reference, reference_sz);
}

static int uadk_keymgmt_rsa_get_params(void *key, OSSL_PARAM params[])
{
    typedef int (*fun_ptr)(void *, OSSL_PARAM *);
    fun_ptr fun = get_default_keymgmt().get_params;
    if (!fun)
        return 0;
    return fun(key, params);
}

static const OSSL_PARAM *uadk_keymgmt_rsa_gettable_params(void *provctx)
{
    typedef const OSSL_PARAM * (*fun_ptr)(void *);
    fun_ptr fun = get_default_keymgmt().gettable_params;
    if (!fun)
        return NULL;
    return fun(provctx);
}

static int uadk_keymgmt_rsa_match(const void *keydata1, const void *keydata2, int selection)
{
    typedef int (*fun_ptr)(const void *, const void *, int);
    fun_ptr fun = get_default_keymgmt().match;
    if (!fun)
        return 0;
    return fun(keydata1, keydata2, selection);
}

static int uadk_keymgmt_rsa_validate(const void *keydata, int selection, int checktype)
{
    typedef int (*fun_ptr)(const void *, int, int);
    fun_ptr fun = get_default_keymgmt().validate;
    if (!fun)
        return 0;
    return fun(keydata, selection, checktype);
}

static int uadk_keymgmt_rsa_export(void *keydata, int selection,
                      OSSL_CALLBACK *param_callback, void *cbarg)
{
    typedef int (*fun_ptr)(void *, int, OSSL_CALLBACK *, void *);
    fun_ptr fun = get_default_keymgmt().export;
    if (!fun)
        return 0;
    return fun(keydata, selection, param_callback, cbarg);
}

static const OSSL_PARAM *uadk_keymgmt_rsa_export_types(int selection)
{
    typedef const OSSL_PARAM * (*fun_ptr)(int);
    fun_ptr fun = get_default_keymgmt().export_types;
    if (!fun)
        return NULL;
    return fun(selection);
}

static void *uadk_keymgmt_rsa_dup(const void *keydata_from, int selection)
{
    typedef void * (*fun_ptr)(const void *, int);
    fun_ptr fun = get_default_keymgmt().dup;
    if (!fun)
        return NULL;
	printf("gzf %s\n", __func__);
    return fun(keydata_from, selection);
}


const OSSL_DISPATCH uadk_rsa_keymgmt_functions[] = {
    {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))uadk_keymgmt_rsa_newdata},
    {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))uadk_keymgmt_rsa_freedata},
    {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))uadk_keymgmt_rsa_has},
    {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))uadk_keymgmt_rsa_import},
    {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))uadk_keymgmt_rsa_import_types},
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))uadk_keymgmt_rsa_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))uadk_keymgmt_rsa_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))uadk_keymgmt_rsa_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))uadk_keymgmt_rsa_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))uadk_keymgmt_rsa_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))uadk_keymgmt_rsa_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))uadk_keymgmt_rsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))uadk_keymgmt_rsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))uadk_keymgmt_rsa_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))uadk_keymgmt_rsa_validate },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))uadk_keymgmt_rsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))uadk_keymgmt_rsa_export_types },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))uadk_keymgmt_rsa_dup },
    {0, NULL}
};

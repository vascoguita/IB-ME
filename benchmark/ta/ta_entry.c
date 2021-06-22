#include <tee_internal_api.h>
#include <ibme_benchmark_ta.h>

#include "ibme_benchmark_ta_private.h"

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result res;

    DMSG("has been called");

    res = benchmark_init();
    if(res != TEE_SUCCESS)
    {
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
    DMSG("has been called");

    benchmark_clear();
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4], void **sess_ctx)
{
    uint32_t exp_param_types;

    (void)&params;
    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
    (void)&sess_ctx;

    DMSG("has been called");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd, uint32_t param_types, TEE_Param params[4])
{
    switch (cmd)
    {
    case TA_IBME_BENCHMARK_CMD_SETUP:
        return benchmark_setup(sess_ctx, param_types, params);
    case TA_IBME_BENCHMARK_CMD_SK_GEN:
        return benchmark_sk_gen(sess_ctx, param_types, params);
    case TA_IBME_BENCHMARK_CMD_RK_GEN:
        return benchmark_rk_gen(sess_ctx, param_types, params);
    case TA_IBME_BENCHMARK_CMD_ENC:
        return benchmark_enc(sess_ctx, param_types, params);
    case TA_IBME_BENCHMARK_CMD_DEC:
        return benchmark_dec(sess_ctx, param_types, params);
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }
}
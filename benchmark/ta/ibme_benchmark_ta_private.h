#ifndef TA_IBME_BENCHMARK_PRIVATE_H
#define TA_IBME_BENCHMARK_PRIVATE_H

#include <tee_internal_api.h>
#include <ibme/ibme.h>

TEE_Result benchmark_init(void);
void benchmark_clear(void);
uint32_t execution_time(TEE_Time start, TEE_Time end);
TEE_Result benchmark_setup(void *sess_ctx, uint32_t param_types, TEE_Param params[4]);
TEE_Result benchmark_sk_gen(void *sess_ctx, uint32_t param_types, TEE_Param params[4]);
TEE_Result benchmark_rk_gen(void *sess_ctx, uint32_t param_types, TEE_Param params[4]);
TEE_Result benchmark_enc(void *sess_ctx, uint32_t param_types, TEE_Param params[4]);
TEE_Result benchmark_dec(void *sess_ctx, uint32_t param_types, TEE_Param params[4]);

#endif //TA_IBME_BENCHMARK_PRIVATE_H
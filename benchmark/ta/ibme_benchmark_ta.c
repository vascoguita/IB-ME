#include <tee_internal_api.h>
#include <ibme/ibme.h>
#include <string.h>

#include <ibme_benchmark_ta.h>
#include "ibme_benchmark_ta_private.h"

static const char S[10];
static const size_t S_size = 10;
static const char R[10];
static const size_t R_size = 10;
static const char m[50];
static const size_t m_size = 50;
char m_dec[50];
size_t m_dec_size = 50;
pairing_t pairing;

static char *param_str = (char *)"type a\nq 87807107996633125224377819847540498158068831994142082110286533992664756308"
                                 "80222957078625179422662221423155858769582317459277713367317481324925129998224791\nh "
                                 "120160122648911460793888213667405342048029544012513118229196151310472072893597045311"
                                 "02844802183906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 15"
                                 "9\nexp1 107\nsign1 1\nsign0 1";

TEE_Result benchmark_init(void)
{
    if(1 == pairing_init_set_str(pairing, param_str))
    {
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

void benchmark_clear(void)
{
    pairing_clear(pairing);
}

uint32_t execution_time(TEE_Time start, TEE_Time end)
{
    TEE_Time rtd_start;
    TEE_Time rtd_end;
    uint32_t rtd;

    TEE_GetSystemTime(&rtd_start);
    TEE_GetSystemTime(&rtd_end);
    rtd = (rtd_end.seconds - rtd_start.seconds) * 1000 + rtd_end.millis - rtd_start.millis;

    return (end.seconds - start.seconds) * 1000 + end.millis - start.millis - rtd;
}

TEE_Result benchmark_setup(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types, *report, *report_size, exp_report_size, i;
    unsigned long rounds;
    TEE_Time start, end;
    MKP *mkp = NULL;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        EMSG("failed checking parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rounds = (unsigned long)params[0].value.a;
    report = params[1].memref.buffer;
    report_size = &(params[1].memref.size);

    if (rounds <= 0)
    {
        EMSG("failed checking parameter values: rounds = %lu", rounds);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    exp_report_size = rounds * sizeof(uint32_t);
    if (*report_size < exp_report_size)
    {
        EMSG("failed checking report buffer size: %" PRIu32 ". Expected size: %" PRIu32, *report_size, exp_report_size);
        *report_size = exp_report_size;
        return TEE_ERROR_SHORT_BUFFER;
    }

    for(i = 0; i < rounds; i++)
    {
        TEE_GetSystemTime(&start);

        if (!(mkp = MKP_init(pairing)))
        {
            return TEE_ERROR_GENERIC;
        }

        if (1 == ibme_setup(mkp))
        {
            MKP_clear(mkp);
            return TEE_ERROR_GENERIC;
        }

        TEE_GetSystemTime(&end);
        report[i] = execution_time(start, end);

        MKP_clear(mkp);
    }

    return TEE_SUCCESS;
}

TEE_Result benchmark_sk_gen(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types, *report, *report_size, exp_report_size, i;
    unsigned long rounds;
    TEE_Time start, end;
    MKP *mkp = NULL;
    EK *ek = NULL;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        EMSG("failed checking parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rounds = (unsigned long)params[0].value.a;
    report = params[1].memref.buffer;
    report_size = &(params[1].memref.size);

    if (rounds <= 0)
    {
        EMSG("failed checking parameter values: rounds = %lu", rounds);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    exp_report_size = rounds * sizeof(uint32_t);
    if (*report_size < exp_report_size)
    {
        EMSG("failed checking report buffer size: %" PRIu32 ". Expected size: %" PRIu32, *report_size, exp_report_size);
        *report_size = exp_report_size;
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (!(mkp = MKP_init(pairing)))
    {
        return TEE_ERROR_GENERIC;
    }

    if (1 == ibme_setup(mkp))
    {
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }

    for(i = 0; i < rounds; i++)
    {
        TEE_GetSystemTime(&start);

        if (!(ek = EK_init(pairing)))
        {
            MKP_clear(mkp);
            return TEE_ERROR_GENERIC;
        }

        if (1 == ibme_sk_gen(pairing, mkp->msk, (unsigned char *)S, S_size, ek))
        {
            EK_clear(ek);
            MKP_clear(mkp);
            return TEE_ERROR_GENERIC;
        }

        TEE_GetSystemTime(&end);
        report[i] = execution_time(start, end);

        EK_clear(ek);
    }

    MKP_clear(mkp);
    return TEE_SUCCESS;
}

TEE_Result benchmark_rk_gen(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types, *report, *report_size, exp_report_size, i;
    unsigned long rounds;
    TEE_Time start, end;
    MKP *mkp = NULL;
    DK *dk = NULL;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        EMSG("failed checking parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rounds = (unsigned long)params[0].value.a;
    report = params[1].memref.buffer;
    report_size = &(params[1].memref.size);

    if (rounds <= 0)
    {
        EMSG("failed checking parameter values: rounds = %lu", rounds);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    exp_report_size = rounds * sizeof(uint32_t);
    if (*report_size < exp_report_size)
    {
        EMSG("failed checking report buffer size: %" PRIu32 ". Expected size: %" PRIu32, *report_size, exp_report_size);
        *report_size = exp_report_size;
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (!(mkp = MKP_init(pairing)))
    {
        return TEE_ERROR_GENERIC;
    }

    if (1 == ibme_setup(mkp))
    {
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }

    for(i = 0; i < rounds; i++)
    {
        TEE_GetSystemTime(&start);

        if (!(dk = DK_init(pairing)))
        {
            MKP_clear(mkp);
            return TEE_ERROR_GENERIC;
        }
        if (1 == ibme_rk_gen(mkp->msk, (unsigned char *)R, R_size, dk))
        {
            DK_clear(dk);
            MKP_clear(mkp);
            return TEE_ERROR_GENERIC;
        }

        TEE_GetSystemTime(&end);
        report[i] = execution_time(start, end);

        DK_clear(dk);
    }

    MKP_clear(mkp);
    return TEE_SUCCESS;
}

TEE_Result benchmark_enc(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types, *report, *report_size, exp_report_size, i;
    unsigned long rounds;
    TEE_Time start, end;
    MKP *mkp = NULL;
    EK *ek = NULL;
    Cipher *c = NULL;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        EMSG("failed checking parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rounds = (unsigned long)params[0].value.a;
    report = params[1].memref.buffer;
    report_size = &(params[1].memref.size);

    if (rounds <= 0)
    {
        EMSG("failed checking parameter values: rounds = %lu", rounds);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    exp_report_size = rounds * sizeof(uint32_t);
    if (*report_size < exp_report_size)
    {
        EMSG("failed checking report buffer size: %" PRIu32 ". Expected size: %" PRIu32, *report_size, exp_report_size);
        *report_size = exp_report_size;
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (!(mkp = MKP_init(pairing)))
    {
        return TEE_ERROR_GENERIC;
    }

    if (1 == ibme_setup(mkp))
    {
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }

    if (!(ek = EK_init(pairing)))
    {
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }

    if (1 == ibme_sk_gen(pairing, mkp->msk, (unsigned char *)S, S_size, ek))
    {
        EK_clear(ek);
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }

    for(i = 0; i < rounds; i++)
    {
        TEE_GetSystemTime(&start);
        if (!(c = Cipher_init(pairing)))
        {
            EK_clear(ek);
            MKP_clear(mkp);
            return TEE_ERROR_GENERIC;
        }
        if (1 == ibme_enc(pairing, mkp->mpk, ek, (unsigned char *)R, R_size, (unsigned char *)m, m_size, c))
        {
            Cipher_clear(c);
            EK_clear(ek);
            MKP_clear(mkp);
            return TEE_ERROR_GENERIC;
        }
        TEE_GetSystemTime(&end);
        report[i] = execution_time(start, end);
        Cipher_clear(c);
    }

    EK_clear(ek);
    MKP_clear(mkp);
    return TEE_SUCCESS;
}

TEE_Result benchmark_dec(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
    uint32_t exp_param_types, *report, *report_size, exp_report_size, i;
    unsigned long rounds;
    TEE_Time start, end;
    MKP *mkp = NULL;
    EK *ek = NULL;
    DK *dk = NULL;
    Cipher *c = NULL;
    size_t tmp_size;

    (void)&sess_ctx;

    DMSG("has been called");

    exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
    if (param_types != exp_param_types)
    {
        EMSG("failed checking parameter types");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    rounds = (unsigned long)params[0].value.a;
    report = params[1].memref.buffer;
    report_size = &(params[1].memref.size);

    if (rounds <= 0)
    {
        EMSG("failed checking parameter values: rounds = %lu", rounds);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    exp_report_size = rounds * sizeof(uint32_t);
    if (*report_size < exp_report_size)
    {
        EMSG("failed checking report buffer size: %" PRIu32 ". Expected size: %" PRIu32, *report_size, exp_report_size);
        *report_size = exp_report_size;
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (!(mkp = MKP_init(pairing)))
    {
        return TEE_ERROR_GENERIC;
    }

    if (1 == ibme_setup(mkp))
    {
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }

    if (!(ek = EK_init(pairing)))
    {
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }

    if (1 == ibme_sk_gen(pairing, mkp->msk, (unsigned char *)S, S_size, ek))
    {
        EK_clear(ek);
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }

    if (!(dk = DK_init(pairing)))
    {
        EK_clear(ek);
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }
    if (1 == ibme_rk_gen(mkp->msk, (unsigned char *)R, R_size, dk))
    {
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }

    if (!(c = Cipher_init(pairing)))
    {
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }
    if (1 == ibme_enc(pairing, mkp->mpk, ek, (unsigned char *)R, R_size, (unsigned char *)m, m_size, c))
    {
        Cipher_clear(c);
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        return TEE_ERROR_GENERIC;
    }

    tmp_size = m_dec_size;

    for(i = 0; i < rounds; i++)
    {
        TEE_GetSystemTime(&start);

        if (1 == ibme_dec(pairing, dk, (unsigned char *)S, S_size, c, (unsigned char *)m_dec, &tmp_size))
        {
            Cipher_clear(c);
            DK_clear(dk);
            EK_clear(ek);
            MKP_clear(mkp);
            return TEE_ERROR_GENERIC;
        }
        
        TEE_GetSystemTime(&end);
        report[i] = execution_time(start, end);
    }

    Cipher_clear(c);
    DK_clear(dk);
    EK_clear(ek);
    MKP_clear(mkp);
    return TEE_SUCCESS;
}
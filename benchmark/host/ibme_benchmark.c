#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <tee_client_api.h>

#include <ibme_benchmark_ta.h>
#include <ibme_benchmark.h>

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt;
    char *operation = NULL;
    char *rounds_str = NULL;
    unsigned long rounds;
    char *p;
    uint32_t commandID;

    while ((opt = getopt(argc, argv, "o:r:")) != -1)
    {
        switch (opt)
        {
        case 'o':
            operation = optarg;
            break;
        case 'r':
            rounds_str = optarg;
            break;
        case ':':
            errx(1, usage, argv[0]);
            break;
        case '?':
            errx(1, usage, argv[0]);
            break;
        }
    }

    if(!rounds_str || !operation)
    {
        errx(1, usage, argv[0]);
    }

    rounds = strtoul(rounds_str, &p, 10);
    if (errno != 0 || *p != '\0')
    {
        errx(1, "failed to read rounds value. %s", strerror(errno));
    }

    if (!strcmp(operation, setup_operation))
    {
        commandID = TA_IBME_BENCHMARK_CMD_SETUP;
    }
    else if (!strcmp(operation, sk_gen_operation))
    {
        commandID = TA_IBME_BENCHMARK_CMD_SK_GEN;
    }
    else if (!strcmp(operation, rk_gen_operation))
    {
        commandID = TA_IBME_BENCHMARK_CMD_RK_GEN;
    }
    else if (!strcmp(operation, enc_operation))
    {
        commandID = TA_IBME_BENCHMARK_CMD_ENC;
    }
    else if (!strcmp(operation, dec_operation))
    {
        commandID = TA_IBME_BENCHMARK_CMD_DEC;
    }
    else
    {
        errx(1, "invalid operation");
    }

    benchmark_operation(commandID, rounds);

    return 0;
}

void prepare_tee_session(TEEC_Context *ctx, TEEC_Session *sess)
{
    TEEC_UUID uuid = TA_IBME_BENCHMARK_UUID;
    uint32_t origin;
    TEEC_Result res;

    res = TEEC_InitializeContext(NULL, ctx);
    if (res != TEEC_SUCCESS)
    {
        errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
    }

    res = TEEC_OpenSession(ctx, sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
    if (res != TEEC_SUCCESS)
    {
        errx(1, "TEEC_OpenSession failed with code 0x%x origin 0x%x", res, origin);
    }
}

void terminate_tee_session(TEEC_Context *ctx, TEEC_Session *sess)
{
    TEEC_CloseSession(sess);
    TEEC_FinalizeContext(ctx);
}

void benchmark_print(uint32_t *report, unsigned long report_len)
{
    unsigned long i;

    for(i = 0; i < report_len; i++)
    {
        if(i == 0)
        {
            printf("%" PRIu32, report[i]);
        }
        else
        {
            printf(",%" PRIu32, report[i]);
        }
    }
    printf("\n");
}

void benchmark_operation(uint32_t commandID, unsigned long rounds)
{
    TEEC_Result res;
    TEEC_Operation op;
    uint32_t err_origin;
    TEEC_Context ctx;
    TEEC_Session sess;
    uint32_t *report = NULL;
    uint32_t report_size;

    report_size = rounds * sizeof(uint32_t);
    report = malloc(report_size);
    if (!report)
    {
        errx(1, "failed to allocating report buffer");
    }

    prepare_tee_session(&ctx, &sess);

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT,
                                    TEEC_NONE, TEEC_NONE);
    op.params[0].value.a = rounds;
    op.params[1].tmpref.buffer = report;
    op.params[1].tmpref.size = report_size;

    res = TEEC_InvokeCommand(&sess, commandID, &op, &err_origin);
    if (res != TEEC_SUCCESS)
    {
        free(report);
        errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
    }

    benchmark_print(report, rounds);

    free(report);
    terminate_tee_session(&ctx, &sess);
}
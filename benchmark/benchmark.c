#include <ibme.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <inttypes.h>
#include "benchmark.h"

int main(int argc, char *argv[])
{
    extern char *optarg;
    int opt;
    char *operation = NULL;
    char *rounds_str = NULL;
    unsigned long rounds;
    char *p;

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

    if (!rounds_str || !operation)
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
        if(benchmark_init())
        {
            errx(1, "\"benchmark_init\" failed.");
        }
        if(benchmark_setup(rounds))
        {
            benchmark_clear();
            errx(1, "\"benchmark_setup\" failed.");
        }
        benchmark_clear();
    }
    else if (!strcmp(operation, sk_gen_operation))
    {
        if(benchmark_init())
        {
            errx(1, "\"benchmark_init\" failed.");
        }
        if(benchmark_sk_gen(rounds))
        {
            benchmark_clear();
            errx(1, "\"benchmark_sk_gen\" failed.");
        }
        benchmark_clear();
    }
    else if (!strcmp(operation, rk_gen_operation))
    {
        if(benchmark_init())
        {
            errx(1, "\"benchmark_init\" failed.");
        }
        if(benchmark_rk_gen(rounds))
        {
            benchmark_clear();
            errx(1, "\"benchmark_rk_gen\" failed.");
        }
        benchmark_clear();
    }
    else if (!strcmp(operation, enc_operation))
    {
        if(benchmark_init())
        {
            errx(1, "\"benchmark_init\" failed.");
        }
        if(benchmark_enc(rounds))
        {
            benchmark_clear();
            errx(1, "\"benchmark_enc\" failed.");
        }
        benchmark_clear();
    }
    else if (!strcmp(operation, dec_operation))
    {
        if(benchmark_init())
        {
            errx(1, "\"benchmark_init\" failed.");
        }
        if(benchmark_dec(rounds))
        {
            benchmark_clear();
            errx(1, "\"benchmark_dec\" failed.");
        }
        benchmark_clear();
    }
    else
    {
        errx(1, "invalid operation");
    }

    return 0;
}

int benchmark_init(void)
{
    if(1 == pairing_init_set_str(pairing, param_str))
    {
        return 1;
    }
}

void benchmark_clear(void)
{
    pairing_clear(pairing);
}

int benchmark_setup(unsigned long rounds)
{
    MKP *mkp;
    unsigned long i;
    clock_t start, end;
    float *report = NULL;
    size_t report_size = 0;

    report_size = rounds;
    if(!(report = malloc(report_size * sizeof(float))))
    {
        return 1;
    }

    for(i = 0; i < rounds; i++)
    {
        start = clock();
        if(1 == MKP_init(pairing, &mkp))
        {
            free(report);
            return 1;
        }

        if(1 == setup(mkp)) {
            MKP_clear(mkp);
            free(report);
            return 1;
        }
        end = clock();
        report[i] = execution_time(start, end);

        MKP_clear(mkp);
    }

    benchmark_print(report, report_size);

    free(report);
    return 0;
}

int benchmark_sk_gen(unsigned long rounds)
{
    MKP *mkp;
    unsigned long i;
    EK *ek;
    clock_t start, end;
    float *report = NULL;
    size_t report_size = 0;

    report_size = rounds;
    if(!(report = malloc(report_size * sizeof(float))))
    {
        return 1;
    }

    if(1 == MKP_init(pairing, &mkp))
    {
        free(report);
        return 1;
    }

    if(1 == setup(mkp))
    {
        MKP_clear(mkp);
        free(report);
        return 1;
    }

    for(i = 0; i < rounds; i++)
    {
        start = clock();
        if(1 == EK_init(pairing, &ek))
        {
            MKP_clear(mkp);
            free(report);
            return 1;
        }

        if(1 == sk_gen(pairing, mkp->msk, (unsigned char *)S, S_size, ek))
        {
            EK_clear(ek);
            MKP_clear(mkp);
            free(report);
            return 1;
        }
        end = clock();
        report[i] = execution_time(start, end);

        EK_clear(ek);
    }

    benchmark_print(report, report_size);

    MKP_clear(mkp);
    free(report);
    return 0;
}

int benchmark_rk_gen(unsigned long rounds)
{
    MKP *mkp;
    unsigned long i;
    DK *dk;
    clock_t start, end;
    float *report = NULL;
    size_t report_size = 0;

    report_size = rounds;
    if(!(report = malloc(report_size * sizeof(float))))
    {
        return 1;
    }

    if(1 == MKP_init(pairing, &mkp))
    {
        return 1;
    }

    if(1 == setup(mkp))
    {
        MKP_clear(mkp);
        free(report);
        return 1;
    }

    for(i = 0; i < rounds; i++)
    {
        start = clock();
        if(1 == DK_init(pairing, &dk))
        {
            MKP_clear(mkp);
            free(report);
            return 1;
        }

        if(1 == rk_gen(mkp->msk, (unsigned char *)R, R_size, dk))
        {
            DK_clear(dk);
            MKP_clear(mkp);
            free(report);
            return 1;
        }
        end = clock();
        report[i] = execution_time(start, end);

        DK_clear(dk);
    }

    benchmark_print(report, report_size);

    MKP_clear(mkp);
    free(report);
    return 0;
}

int benchmark_enc(unsigned long rounds)
{
    MKP *mkp;
    unsigned long i;
    EK *ek;
    Cipher *c;
    clock_t start, end;
    float *report = NULL;
    size_t report_size = 0;

    report_size = rounds;
    if(!(report = malloc(report_size * sizeof(float))))
    {
        return 1;
    }

    if(1 == MKP_init(pairing, &mkp))
    {
        free(report);
        return 1;
    }

    if(1 == setup(mkp))
    {
        MKP_clear(mkp);
        free(report);
        return 1;
    }

    if(1 == EK_init(pairing, &ek))
    {
        MKP_clear(mkp);
        free(report);
        return 1;
    }

    if(1 == sk_gen(pairing, mkp->msk, (unsigned char *)S, S_size, ek))
    {
        EK_clear(ek);
        MKP_clear(mkp);
        free(report);
        return 1;
    }

    for(i = 0; i < rounds; i++)
    {
        start = clock();
        if(1 == Cipher_init(pairing, &c))
        {
            EK_clear(ek);
            MKP_clear(mkp);
            free(report);
            return 1;
        }
        
        if(1 == enc(pairing, mkp->mpk, ek, (unsigned char *)R, R_size, (unsigned char *)m, m_size, c))
        {
            Cipher_clear(c);
            EK_clear(ek);
            MKP_clear(mkp);
            free(report);
            return 1;
        }
        end = clock();
        report[i] = execution_time(start, end);

        Cipher_clear(c);
    }

    benchmark_print(report, report_size);

    EK_clear(ek);
    MKP_clear(mkp);
    free(report);
    return 0;
}

int benchmark_dec(unsigned long rounds)
{
    MKP *mkp;
    unsigned long i;
    EK *ek;
    DK *dk;
    Cipher *c;
    size_t tmp_size;
    clock_t start, end;
    float *report = NULL;
    size_t report_size = 0;

    report_size = rounds;
    if(!(report = malloc(report_size * sizeof(float))))
    {
        return 1;
    }

    if(1 == MKP_init(pairing, &mkp))
    {
        free(report);
        return 1;
    }

    if(1 == setup(mkp))
    {
        MKP_clear(mkp);
        free(report);
        return 1;
    }

    if(1 == EK_init(pairing, &ek))
    {
        MKP_clear(mkp);
        free(report);
        return 1;
    }

    if(1 == sk_gen(pairing, mkp->msk, (unsigned char *)S, S_size, ek))
    {
        EK_clear(ek);
        MKP_clear(mkp);
        free(report);
        return 1;
    }

    if(1 == DK_init(pairing, &dk))
    {
        EK_clear(ek);
        MKP_clear(mkp);
        free(report);
        return 1;
    }

    if(1 == rk_gen(mkp->msk, (unsigned char *)R, R_size, dk))
    {
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        free(report);
        return 1;
    }

    if(1 == Cipher_init(pairing, &c))
    {
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        free(report);
        return 1;
    }
    
    if(1 == enc(pairing, mkp->mpk, ek, (unsigned char *)R, R_size, (unsigned char *)m, m_size, c))
    {
        Cipher_clear(c);
        DK_clear(dk);
        EK_clear(ek);
        MKP_clear(mkp);
        free(report);
        return 1;
    }

    tmp_size = m_dec_size;

    for(i = 0; i < rounds; i++)
    {
        start = clock();
        if(1 == dec(pairing, dk, (unsigned char *)S, S_size, c, (unsigned char *)m_dec, &tmp_size))
        {
            Cipher_clear(c);
            DK_clear(dk);
            EK_clear(ek);
            MKP_clear(mkp);
            free(report);
            return 1;
        }
        if(tmp_size != m_dec_size)
        {
            Cipher_clear(c);
            DK_clear(dk);
            EK_clear(ek);
            MKP_clear(mkp);
            free(report);
            return 1;
        }
        end = clock();
        report[i] = execution_time(start, end);
    }

    benchmark_print(report, report_size);

    Cipher_clear(c);
    DK_clear(dk);
    EK_clear(ek);
    MKP_clear(mkp);
    free(report);
    return 0;
}

float execution_time(clock_t start, clock_t end)
{
    clock_t rtd_start;
    clock_t rtd_end;
    float rtd;

    rtd_start = clock();
    rtd_end = clock();
    rtd = (rtd_end - rtd_start) / (float)(CLOCKS_PER_SEC / (float)1000);

    return ((end - start) / (float)(CLOCKS_PER_SEC / (float)1000)) - rtd;
}

void benchmark_print(float *report, size_t report_size)
{
    size_t i;

    for(i = 0; i < report_size; i++)
    {
        if(i == 0)
        {
            printf("%.3f", report[i]);
        }
        else
        {
            printf(",%.3f", report[i]);
        }
    }
    printf("\n");
}
#ifndef IBME_BENCHMARK_H
#define IBME_BENCHMARK_H

#include <ibme.h>

static const char usage[] = "usage: %s -o operation -r rounds\n";
static const char setup_operation[] = "setup";
static const char sk_gen_operation[] = "sk_gen";
static const char rk_gen_operation[] = "rk_gen";
static const char enc_operation[] = "enc";
static const char dec_operation[] = "dec";

static const char S[10];
static const size_t S_size = 10;
static const char R[10];
static const size_t R_size = 10;
static const char m[50];
static const size_t m_size = 50;
char m_dec[50];
size_t m_dec_size = 50;
pairing_t pairing;

static char *param_str = "type a\nq 87807107996633125224377819847540498158068831994142082110286533992664756308802"
                         "22957078625179422662221423155858769582317459277713367317481324925129998224791\nh 120160"
                         "122648911460793888213667405342048029544012513118229196151310472072893597045311028448021"
                         "83906537786776\nr 730750818665451621361119245571504901405976559617\nexp2 159\nexp1 107"
                         "\nsign1 1\nsign0 1";

int benchmark_init(void);
void benchmark_clear(void);
int benchmark_setup(unsigned long rounds);
int benchmark_sk_gen(unsigned long rounds);
int benchmark_rk_gen(unsigned long rounds);
int benchmark_enc(unsigned long rounds);
int benchmark_dec(unsigned long rounds);

float execution_time(clock_t start, clock_t end);
void benchmark_print(float *report, size_t report_size);

#endif //IBME_BENCHMARK_H

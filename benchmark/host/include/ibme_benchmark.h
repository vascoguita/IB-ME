#ifndef IBME_BENCHMARK_H
#define IBME_BENCHMARK_H

#include <stdio.h>
#include <tee_client_api.h>

static const char usage[] = "usage: %s -o operation -r rounds\n";
static const char setup_operation[] = "setup";
static const char sk_gen_operation[] = "sk_gen";
static const char rk_gen_operation[] = "rk_gen";
static const char enc_operation[] = "enc";
static const char dec_operation[] = "dec";

void benchmark_operation(uint32_t commandID, unsigned long rounds);
void prepare_tee_session(TEEC_Context *ctx, TEEC_Session *sess);
void terminate_tee_session(TEEC_Context *ctx, TEEC_Session *sess);
void benchmark_print(uint32_t *report, unsigned long report_len);

#endif
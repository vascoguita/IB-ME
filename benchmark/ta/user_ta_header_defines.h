#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <ibme_benchmark_ta.h>

#define TA_UUID         TA_IBME_BENCHMARK_UUID

#define TA_FLAGS        TA_FLAG_EXEC_DDR

#define TA_STACK_SIZE   (8 * 1024)
#define TA_DATA_SIZE    (64 * 1024)

#define TA_VERSION	"0.1"

#define TA_DESCRIPTION	"TA for assessing the performance of the IB-ME library"

#endif
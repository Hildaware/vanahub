#pragma once

#include <stdint.h>

#if defined(_WIN32)
#  if defined(VH_ENGINE_BUILD)
#    define VH_API extern "C" __declspec(dllexport)
#  else
#    define VH_API extern "C" __declspec(dllimport)
#  endif
#  define VH_CALL __cdecl
#else
#  define VH_API extern "C"
#  define VH_CALL
#endif

typedef struct vh_engine vh_engine;
typedef uint64_t vh_job_id;

typedef enum vh_result {
    VH_OK = 0,
    VH_INVALID_ARGUMENT = 1,
    VH_ABI_MISMATCH = 2,
    VH_NOT_FOUND = 3,
    VH_BUFFER_TOO_SMALL = 4,
    VH_BUSY = 5,
    VH_CANCELLED = 6,
    VH_NETWORK_ERROR = 7,
    VH_HASH_MISMATCH = 8,
    VH_SCAN_REJECTED = 9,
    VH_ARCHIVE_ERROR = 10,
    VH_FILESYSTEM_ERROR = 11,
    VH_INTERNAL_ERROR = 12
} vh_result;

#define VH_ABI_VERSION 1u

VH_API uint32_t VH_CALL vh_abi_version(void);
VH_API vh_result VH_CALL vh_engine_create(const char* config_json, vh_engine** engine);
VH_API vh_result VH_CALL vh_engine_recover(vh_engine* engine);
VH_API vh_job_id VH_CALL vh_job_start(vh_engine* engine, const char* request_json);
VH_API vh_result VH_CALL vh_job_poll(vh_engine* engine, vh_job_id job, char* status_json,
                                     uint32_t capacity, uint32_t* required);
VH_API vh_result VH_CALL vh_job_cancel(vh_engine* engine, vh_job_id job);
VH_API void VH_CALL vh_job_release(vh_engine* engine, vh_job_id job);
VH_API void VH_CALL vh_engine_destroy(vh_engine* engine);

#pragma once

#include <stdint.h>

#if defined(_WIN32)
#  if defined(XR_ENGINE_BUILD)
#    define XR_API extern "C" __declspec(dllexport)
#  else
#    define XR_API extern "C" __declspec(dllimport)
#  endif
#  define XR_CALL __cdecl
#else
#  define XR_API extern "C"
#  define XR_CALL
#endif

typedef struct xr_engine xr_engine;
typedef uint64_t xr_job_id;

typedef enum xr_result {
    XR_OK = 0,
    XR_INVALID_ARGUMENT = 1,
    XR_ABI_MISMATCH = 2,
    XR_NOT_FOUND = 3,
    XR_BUFFER_TOO_SMALL = 4,
    XR_BUSY = 5,
    XR_CANCELLED = 6,
    XR_NETWORK_ERROR = 7,
    XR_HASH_MISMATCH = 8,
    XR_SCAN_REJECTED = 9,
    XR_ARCHIVE_ERROR = 10,
    XR_FILESYSTEM_ERROR = 11,
    XR_INTERNAL_ERROR = 12
} xr_result;

#define XR_ABI_VERSION 1u

XR_API uint32_t XR_CALL xr_abi_version(void);
XR_API xr_result XR_CALL xr_engine_create(const char* config_json, xr_engine** engine);
XR_API xr_result XR_CALL xr_engine_recover(xr_engine* engine);
XR_API xr_job_id XR_CALL xr_job_start(xr_engine* engine, const char* request_json);
XR_API xr_result XR_CALL xr_job_poll(xr_engine* engine, xr_job_id job, char* status_json,
                                     uint32_t capacity, uint32_t* required);
XR_API xr_result XR_CALL xr_job_cancel(xr_engine* engine, xr_job_id job);
XR_API void XR_CALL xr_job_release(xr_engine* engine, xr_job_id job);
XR_API void XR_CALL xr_engine_destroy(xr_engine* engine);

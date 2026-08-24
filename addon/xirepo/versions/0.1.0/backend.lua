local ffi = require 'ffi';

ffi.cdef[[
    typedef struct xr_engine xr_engine;
    typedef uint64_t xr_job_id;
    typedef int xr_result;
    uint32_t xr_abi_version(void);
    xr_result xr_engine_create(const char* config_json, xr_engine** engine);
    xr_result xr_engine_recover(xr_engine* engine);
    xr_job_id xr_job_start(xr_engine* engine, const char* request_json);
    xr_result xr_job_poll(xr_engine* engine, xr_job_id job, char* status_json,
                          uint32_t capacity, uint32_t* required);
    xr_result xr_job_cancel(xr_engine* engine, xr_job_id job);
    void xr_job_release(xr_engine* engine, xr_job_id job);
    void xr_engine_destroy(xr_engine* engine);
]];

local backend = { available = false, error = nil, jobs = { } };
local XR_OK = 0;
local XR_BUFFER_TOO_SMALL = 4;

local function escape(value)
    return tostring(value):gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\r', '\\r'):gsub('\n', '\\n');
end

function backend.encode(value)
    local kind = type(value);
    if kind == 'string' then return '"' .. escape(value) .. '"'; end
    if kind == 'boolean' or kind == 'number' then return tostring(value); end
    if kind == 'table' then
        local parts = { };
        for key, item in pairs(value) do
            parts[#parts + 1] = backend.encode(tostring(key)) .. ':' .. backend.encode(item);
        end
        return '{' .. table.concat(parts, ',') .. '}';
    end
    return 'null';
end

function backend.initialize(version_root, builtin_public_key)
    local path = version_root .. 'bin\\xirepo_engine.dll';
    local ok, library = pcall(ffi.load, path);
    if not ok then backend.error = 'Native engine not found: ' .. tostring(library); return false; end
    if tonumber(library.xr_abi_version()) ~= 1 then backend.error = 'Native engine ABI mismatch.'; return false; end
    local engine_out = ffi.new('xr_engine*[1]');
    local install_root = AshitaCore:GetInstallPath() .. '\\addons';
    local cache_root = AshitaCore:GetInstallPath() .. '\\config\\addons\\xirepo\\cache';
    local config = backend.encode({ installRoot = install_root, cacheRoot = cache_root, builtinPublicKey = builtin_public_key or '' });
    local result = library.xr_engine_create(config, engine_out);
    if result ~= XR_OK then backend.error = 'Native engine initialization failed: ' .. tonumber(result); return false; end
    backend.library = library;
    backend.engine = engine_out[0];
    backend.library.xr_engine_recover(backend.engine);
    backend.available = true;
    return true;
end

function backend.start(request)
    if not backend.available then return nil, backend.error; end
    local id = backend.library.xr_job_start(backend.engine, backend.encode(request));
    if id == 0 then return nil, 'The native engine rejected the job.'; end
    local key = tostring(tonumber(id));
    backend.jobs[key] = { id = id, phase = 'queued', message = '', terminal = false, result = 0 };
    return backend.jobs[key];
end

function backend.poll(job)
    if not backend.available or job == nil then return job; end
    local required = ffi.new('uint32_t[1]');
    local result = backend.library.xr_job_poll(backend.engine, job.id, nil, 0, required);
    if result ~= XR_BUFFER_TOO_SMALL then return job; end
    local buffer = ffi.new('char[?]', required[0]);
    result = backend.library.xr_job_poll(backend.engine, job.id, buffer, required[0], required);
    if result ~= XR_OK then return job; end
    local text = ffi.string(buffer);
    job.phase = text:match('"phase":"([^"]*)"') or job.phase;
    job.message = text:match('"message":"([^"]*)"') or job.message;
    job.terminal = text:match('"terminal":true') ~= nil;
    job.result = tonumber(text:match('"result":([0-9]+)')) or job.result;
    job.completed = tonumber(text:match('"completed":([0-9]+)')) or 0;
    job.total = tonumber(text:match('"total":([0-9]+)')) or 0;
    return job;
end

function backend.cancel(job)
    if backend.available and job ~= nil then backend.library.xr_job_cancel(backend.engine, job.id); end
end

function backend.release(job)
    if backend.available and job ~= nil then
        backend.library.xr_job_release(backend.engine, job.id);
        backend.jobs[tostring(tonumber(job.id))] = nil;
    end
end

function backend.shutdown()
    if backend.available then
        backend.library.xr_engine_destroy(backend.engine);
        backend.engine = nil;
        backend.available = false;
    end
end

return backend;

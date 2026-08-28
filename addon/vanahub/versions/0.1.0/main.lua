require 'common';

local imgui = require 'imgui';
local chat = require 'chat';
local json = require 'json';
local ffi = require 'ffi';
local d3d8 = require 'd3d8';
local backend = require 'backend';
local builtin = require 'builtin';
local profiles = require 'profiles';

local install_root = AshitaCore:GetInstallPath() .. '\\addons\\';
local config_root = AshitaCore:GetInstallPath() .. '\\config\\addons\\vanahub\\';
local profile_root = config_root .. 'profiles\\';
local profile_export_root = profile_root .. 'exports\\';
local profile_import_root = profile_root .. 'imports\\';
local state_path = config_root .. 'state.json';
local repository_path = config_root .. 'repositories.json';
local state = {
    schemaVersion = 3,
    visible = T{ false }, search = T{ '' }, selected = nil, packages = { }, installed = { },
    profile_search = T{ '' }, selected_catalog_profile = nil, catalog_profiles = { },
    profiles = { }, activeProfileId = nil, profile_name = T{ '' }, profile_editor = nil,
    confirm_delete_profile = nil, repositories = { }, operation = nil, operation_context = nil, notice = nil,
    revocations = { }, addon_action = nil, startup = { ready = false, started = false },
    media = { cache = { }, queue = { }, job = nil, request = nil }, transfer = { mode = nil },
    custom_url = T{ '' }, custom_ack = T{ false }, developer_mode = T{ false }, consent_package = nil,
};

local function read_text(path)
    local file = io.open(path, 'rb');
    if file == nil then return nil; end
    local value = file:read('*all'); file:close(); return value;
end

local function write_text(path, value)
    local temporary = path .. '.tmp';
    local file = io.open(temporary, 'wb');
    if file == nil then return false; end
    file:write(value); file:close();
    if ashita.fs.exists(path) then ashita.fs.remove(path); end
    return ashita.fs.rename(temporary, path);
end

local function decode(value)
    if value == nil then return nil; end
    local ok, result = pcall(json.decode, value); return ok and result or nil;
end

local function encode(value)
    local ok, result = pcall(json.encode, value); return ok and result or '{}';
end

local function is_safe_package_id(value)
    return type(value) == 'string' and #value >= 2 and #value <= 64
        and value:match('^[a-z0-9][a-z0-9._-]+$') ~= nil;
end

local function load_state()
    local raw = decode(read_text(state_path));
    local installed = raw;
    if type(raw) == 'table' and (raw.schemaVersion == 2 or raw.schemaVersion == 3) then installed = raw.installed; end
    if type(installed) ~= 'table' then installed = { }; end
    state.installed = installed;
    for id, _ in pairs(state.installed) do
        if not is_safe_package_id(id)
            or not ashita.fs.exists(install_root .. id .. '\\.vanahub-owned') then state.installed[id] = nil; end
    end
    local document = profiles.normalize(raw, state.installed);
    state.profiles = document.profiles;
    state.activeProfileId = document.activeProfileId;
    state.repositories = {
        { id = 'builtin', name = 'Built-in screened repository', url = builtin.index_url, signature_url = builtin.signature_url, builtin = true, enabled = true },
    };
    local repositories = decode(read_text(repository_path));
    if type(repositories) == 'table' then
        for _, repository in ipairs(repositories) do
            if type(repository) == 'table' and type(repository.url) == 'string' and not repository.builtin then
                state.repositories[#state.repositories + 1] = repository;
            end
        end
    end
end

local function save_state()
    local state_saved = write_text(state_path, encode({
        schemaVersion = 3,
        installed = state.installed,
        profiles = state.profiles,
        activeProfileId = state.activeProfileId,
    }));
    local custom = { };
    for _, repository in ipairs(state.repositories) do
        if not repository.builtin then custom[#custom + 1] = repository; end
    end
    local repositories_saved = write_text(repository_path, encode(custom));
    if not state_saved or not repositories_saved then
        state.notice = 'Could not save VanaHub settings.';
        return false;
    end
    return true;
end

local function rebuild_packages()
    local selected_id = state.selected and state.selected.id or nil;
    local selected_repository = state.selected and state.selected._repository and state.selected._repository.id or nil;
    local selected_profile_id = state.selected_catalog_profile and state.selected_catalog_profile.id or nil;
    local selected_profile_repository = state.selected_catalog_profile and state.selected_catalog_profile._repository
        and state.selected_catalog_profile._repository.id or nil;
    local packages, catalog_profiles = { }, { };
    local revocations = { };
    for _, repository in ipairs(state.repositories) do
        if repository.enabled and repository.builtin and type(repository.revocations) == 'table' then
            for _, revocation in ipairs(repository.revocations) do
                if type(revocation) == 'table' and type(revocation.sha256) == 'string' then revocations[revocation.sha256] = revocation; end
            end
        end
    end
    for _, repository in ipairs(state.repositories) do
        if repository.enabled and type(repository.packages) == 'table' then
            for _, package in ipairs(repository.packages) do
                if type(package) == 'table' and type(package.id) == 'string' then
                    package._revocation = revocations[package.sha256];
                    if state.installed[package.id] == nil
                        and ashita.fs.exists(install_root .. package.id .. '\\.vanahub-owned') then
                        state.installed[package.id] = {
                            id = package.id, name = package.name, version = package.version,
                            sha256 = package.sha256, source = repository.id,
                        };
                        profiles.add_installed(state, package.id);
                    end
                    package._repository = repository; packages[#packages + 1] = package;
                end
            end
        end
        if repository.enabled and type(repository.profiles) == 'table' then
            for _, profile in ipairs(repository.profiles) do
                if profiles.validate_catalog(profile) then
                    profile._repository = repository; catalog_profiles[#catalog_profiles + 1] = profile;
                end
            end
        end
    end
    table.sort(packages, function (a, b)
        if a.id == b.id then return a._repository.builtin and not b._repository.builtin; end
        return (a.name or a.id):lower() < (b.name or b.id):lower();
    end);
    table.sort(catalog_profiles, function (a, b)
        if a.id == b.id then return a._repository.builtin and not b._repository.builtin; end
        return (a.name or a.id):lower() < (b.name or b.id):lower();
    end);
    state.packages = packages; state.catalog_profiles = catalog_profiles;
    state.revocations = revocations; state.selected = nil; state.selected_catalog_profile = nil;
    if selected_id ~= nil then
        for _, package in ipairs(packages) do
            if package.id == selected_id and package._repository.id == selected_repository then state.selected = package; break; end
        end
    end
    if selected_profile_id ~= nil then
        for _, profile in ipairs(catalog_profiles) do
            if profile.id == selected_profile_id and profile._repository.id == selected_profile_repository then
                state.selected_catalog_profile = profile; break;
            end
        end
    end
end

local function load_repository(repository, path)
    local document = decode(read_text(path));
    if type(document) ~= 'table' or document.schemaVersion ~= 1 or type(document.packages) ~= 'table' then
        state.notice = 'Repository index is invalid: ' .. tostring(repository.name); return false;
    end
    repository.name = document.repository and document.repository.name or repository.name;
    repository.packages = document.packages; repository.profiles = document.profiles or { };
    repository.revocations = document.revocations or { };
    repository.generated_at = document.generatedAt;
    repository.loaded = true; rebuild_packages(); save_state(); return true;
end

local function start_repository_refresh(repository)
    if not backend.available or repository.url == '' or state.operation ~= nil then return; end
    local job, err = backend.start({
        operation = 'fetchRepository', packageId = repository.id,
        url = repository.url, sha256 = repository.sha256 or '', allowLocal = repository.local_source == true,
        requireSignature = repository.builtin == true, signatureUrl = repository.signature_url or '',
    });
    if job == nil then state.notice = err; return; end
    repository.status = repository.loaded and 'refreshing (cached)' or 'refreshing';
    state.operation = job; state.operation_context = { kind = 'repository', repository = repository };
end

local function start_repository_cache(repository)
    if not backend.available or state.operation ~= nil then return; end
    local job, err = backend.start({
        operation = 'loadRepositoryCache', packageId = repository.id, requireSignature = repository.builtin == true,
    });
    if job == nil then
        state.notice = err; state.startup.ready = true; start_repository_refresh(repository); return;
    end
    repository.status = 'loading cache';
    state.operation = job; state.operation_context = { kind = 'repository-cache', repository = repository };
end

local function start_install(package, allow_elevated)
    local job, err = backend.start({
        operation = package.id == 'vanahub' and 'stageSelfUpdate' or (state.installed[package.id] and 'update' or 'install'),
        packageId = package.id, url = package.downloadUrl, sha256 = package.sha256,
        version = package.version,
        archiveRoot = package.archiveRoot or '', entrypoint = package.entrypoint,
        allowElevated = allow_elevated == true, allowLocal = package._repository.local_source == true,
        githubOnly = package._repository.builtin == true,
    });
    if job == nil then state.notice = err; return; end
    state.operation = job; state.operation_context = { kind = 'install', package = package };
    state.notice = 'Installing ' .. (package.name or package.id) .. '...';
end

local function start_uninstall(package_id)
    local job, err = backend.start({ operation = 'uninstall', packageId = package_id });
    if job == nil then state.notice = err; return; end
    state.operation = job; state.operation_context = { kind = 'uninstall', packageId = package_id };
    state.notice = 'Uninstalling ' .. package_id .. '...';
end

local function is_addon_loaded(package_id)
    if AddonManager == nil or AddonManager.IsLoaded == nil then return nil; end
    local ok, loaded = pcall(function () return AddonManager:IsLoaded(package_id); end);
    if not ok then return nil; end
    return loaded == true;
end

local function set_addon_loaded(package_id, enabled, startup)
    if not is_safe_package_id(package_id) then
        state.notice = 'Refusing to load an invalid package id.'; return;
    end
    local action = enabled and 'load' or 'unload';
    AshitaCore:GetChatManager():QueueCommand(-1, '/addon ' .. action .. ' ' .. package_id);
    state.addon_action = {
        packageId = package_id, enabled = enabled, started = ashita.time.get_tick64(), startup = startup == true,
    };
    state.notice = (enabled and 'Loading ' or 'Unloading ') .. package_id .. '...';
end

local function tick_addon_action()
    local action = state.addon_action;
    if action == nil then return; end
    local loaded = is_addon_loaded(action.packageId);
    if loaded ~= nil and loaded == action.enabled then
        state.notice = action.packageId .. (action.enabled and ' loaded.' or ' unloaded.');
        if action.startup then state.startup.loaded = state.startup.loaded + 1; end
        state.addon_action = nil;
    elseif ashita.time.get_tick64() - action.started >= 5000 then
        local message = 'Could not confirm that ' .. action.packageId
            .. (action.enabled and ' loaded.' or ' unloaded.');
        state.notice = message;
        if action.startup then state.startup.failures[#state.startup.failures + 1] = message; end
        state.addon_action = nil;
    end
end

local function repository_for_id(id)
    for _, repository in ipairs(state.repositories) do if repository.id == id then return repository; end end
    return nil;
end

local function package_for_import(entry)
    for _, package in ipairs(state.packages) do
        local source = entry.source or { builtin = true };
        if package.id == entry.id and package._revocation == nil
            and ((source.builtin == true and package._repository.builtin == true)
                or (source.builtin ~= true and package._repository.url == source.url)) then return package; end
    end
    return nil;
end

local function begin_profile_export()
    local profile = profiles.active(state);
    local include = { };
    for _, entry in ipairs(profile and profile.addons or { }) do
        if entry.id ~= 'vanahub' and state.installed[entry.id] ~= nil then include[entry.id] = T{ true }; end
    end
    local safe_name = (profile and profile.name or 'profile'):gsub('[^%w._-]+', '-'):gsub('^-+', ''):gsub('-+$', '');
    if safe_name == '' then safe_name = 'profile'; end
    state.transfer = { mode = 'export', include = include,
        filename = T{ safe_name .. '.vanahub-profile.zip' } };
end

local function start_profile_export()
    local profile = profiles.active(state);
    if profile == nil then return; end
    local filename = tostring(state.transfer.filename[1] or ''):match('^%s*(.-)%s*$');
    if filename == '' or #filename > 160 or filename:match('^[A-Za-z0-9][A-Za-z0-9._-]*$') == nil then
        state.notice = 'Export filename may contain only letters, numbers, dots, underscores, and hyphens.'; return;
    end
    if filename:lower():sub(-20) ~= '.vanahub-profile.zip' then filename = filename .. '.vanahub-profile.zip'; end
    local output = profile_export_root .. filename;
    if ashita.fs.exists(output) and state.transfer.confirm_overwrite ~= output then
        state.transfer.confirm_overwrite = output;
        state.notice = 'That export already exists. Select Confirm overwrite to replace it.'; return;
    end
    local manifest = { schemaVersion = 1, profile = { name = profile.name, addons = { } } };
    local ids = { };
    for _, entry in ipairs(profile.addons) do
        if entry.id ~= 'vanahub' then
            local installed = state.installed[entry.id];
            local source = entry.source or { builtin = true };
            local repository = installed and repository_for_id(installed.source) or nil;
            if repository ~= nil and not repository.builtin and type(repository.url) == 'string'
                and repository.url:match('^https://') ~= nil then
                source = { builtin = false, name = repository.name, url = repository.url };
            elseif installed ~= nil and installed.source ~= 'builtin'
                and (repository == nil or repository.builtin ~= true) then
                state.notice = entry.id .. ' uses a non-portable custom repository and cannot be exported.';
                return;
            end
            local include = state.transfer.include[entry.id];
            local portable = {
                id = entry.id, autoLoad = entry.autoLoad == true,
                version = installed and installed.version or entry.version,
                sha256 = installed and installed.sha256 or entry.sha256,
                source = source, settings = include ~= nil and include[1] == true,
            };
            manifest.profile.addons[#manifest.profile.addons + 1] = portable;
            if portable.settings then ids[#ids + 1] = entry.id; end
        end
    end
    local manifest_path = config_root .. 'cache\\profile-export.json';
    ashita.fs.create_directory(config_root .. 'cache');
    if not write_text(manifest_path, encode(manifest)) then state.notice = 'Could not stage the profile manifest.'; return; end
    local job, err = backend.start({ operation = 'exportProfile', packageId = 'profile-transfer',
        manifestPath = manifest_path, outputPath = output, packageIds = table.concat(ids, ';') });
    if job == nil then state.notice = err; return; end
    state.operation = job; state.operation_context = { kind = 'profile-export' };
    state.notice = 'Scanning settings and exporting ' .. profile.name .. '...';
end

local function load_import_review(staging, supplied_manifest, catalog_profile)
    local manifest = supplied_manifest or decode(read_text(staging .. '\\profile.json'));
    local valid, err = profiles.validate_import(manifest);
    if not valid then state.notice = err; state.transfer = { mode = nil }; return; end
    local review = { mode = 'import', phase = 'review', staging = staging, manifest = manifest,
        catalog_profile = catalog_profile, entries = { }, repositories = { }, errors = { } };
    local repository_by_url = { };
    for _, repository in ipairs(state.repositories) do
        if type(repository.url) == 'string' then repository_by_url[repository.url] = repository; end
    end
    for _, source in ipairs(manifest.profile.addons) do
        local item = { source = source, install = T{ source.source == nil or source.source.builtin == true },
            settings = T{ source.settings == true }, skipSettings = false };
        if source.source ~= nil and source.source.builtin ~= true then
            local portable = review.repositories[source.source.url];
            if portable == nil then
                portable = { url = source.source.url, name = source.source.name or source.source.url,
                    approved = T{ repository_by_url[source.source.url] ~= nil }, existing = repository_by_url[source.source.url] };
                review.repositories[source.source.url] = portable;
            end
            item.repository = portable; item.install[1] = false;
        end
        local installed = state.installed[source.id];
        if installed ~= nil then
            local local_repository = repository_for_id(installed.source);
            local expected_builtin = source.source == nil or source.source.builtin == true;
            item.sourceMismatch = local_repository == nil
                or (expected_builtin and local_repository.builtin ~= true)
                or (not expected_builtin and local_repository.url ~= source.source.url);
            if item.sourceMismatch then item.settings[1] = false; end
        end
        review.entries[#review.entries + 1] = item;
    end
    state.transfer = review;
end

local function begin_catalog_profile_import(profile)
    local valid, err = profiles.validate_catalog(profile);
    if not valid then state.notice = err; return; end
    local repository = profile._repository;
    if type(repository) ~= 'table' then state.notice = 'Profile catalog source is unavailable.'; return; end
    local job, start_error = backend.start({ operation = 'inspectCatalogProfile', packageId = 'profile-transfer',
        url = profile.downloadUrl, sha256 = profile.sha256, compressedSize = profile.compressedSize,
        allowLocal = repository.local_source == true, githubOnly = repository.builtin == true });
    if job == nil then state.notice = start_error; return; end
    state.transfer = { mode = 'import', phase = 'downloading', catalog_profile = profile };
    state.operation = job; state.operation_context = { kind = 'catalog-profile-inspect', profile = profile };
    state.notice = 'Downloading and scanning ' .. profile.name .. '...';
end

local function begin_profile_import()
    state.transfer = { mode = 'import', phase = 'choose', input_path = T{ '' } };
end

local function start_profile_import()
    local input = tostring(state.transfer.input_path[1] or ''):match('^%s*(.-)%s*$');
    input = input:match('^"(.*)"$') or input;
    if input == '' or #input > 4096 then state.notice = 'Paste a valid profile archive path.'; return; end
    if input:find('[\\/]') == nil then
        if input:match('^[A-Za-z0-9][A-Za-z0-9._-]*$') == nil then
            state.notice = 'Import filenames may contain only letters, numbers, dots, underscores, and hyphens.'; return;
        end
        input = profile_import_root .. input;
    end
    local job, err = backend.start({ operation = 'inspectProfile', packageId = 'profile-transfer', inputPath = input });
    if job == nil then state.notice = err; return; end
    state.operation = job; state.operation_context = { kind = 'profile-inspect' };
    state.transfer.phase = 'inspecting';
    state.notice = 'Inspecting and scanning the profile archive...';
end

local function confirm_profile_import()
    local transfer = state.transfer; transfer.repository_queue = { };
    for _, portable in pairs(transfer.repositories) do
        if portable.approved[1] and portable.existing == nil then
            local repository = { id = 'imported-' .. tostring(#state.repositories), name = portable.name,
                url = portable.url, builtin = false, enabled = true };
            state.repositories[#state.repositories + 1] = repository; portable.existing = repository;
            transfer.repository_queue[#transfer.repository_queue + 1] = repository;
        end
    end
    save_state(); transfer.phase = 'repositories'; transfer.install_index = 1;
end

local function advance_profile_import()
    local transfer = state.transfer;
    if transfer.mode ~= 'import' or transfer.phase == 'review' or transfer.phase == 'inspecting'
        or transfer.phase == 'summary' or state.operation ~= nil or state.addon_action ~= nil then return; end
    if transfer.phase == 'repositories' then
        local repository = table.remove(transfer.repository_queue, 1);
        if repository ~= nil then
            start_repository_refresh(repository);
            if state.operation ~= nil then state.operation_context.transfer = true; end
            return;
        end
        transfer.phase = 'installing'; transfer.install_index = 1;
    end
    if transfer.phase == 'installing' then
        while transfer.install_index <= #transfer.entries do
            local item = transfer.entries[transfer.install_index]; transfer.install_index = transfer.install_index + 1;
            local source = item.source;
            if state.installed[source.id] == nil and item.install[1] then
                if item.repository ~= nil and not item.repository.approved[1] then
                    transfer.errors[#transfer.errors + 1] = source.id .. ': custom repository was not trusted.';
                else
                    local package = package_for_import(source);
                    if package ~= nil then
                        if source.version ~= nil and source.version ~= package.version then
                            transfer.errors[#transfer.errors + 1] = source.id .. ': imported ' .. source.version
                                .. ', installed current ' .. tostring(package.version) .. '.';
                        end
                        start_install(package, package._repository.builtin ~= true);
                        if state.operation ~= nil then state.operation_context.transfer = true; return;
                        else transfer.errors[#transfer.errors + 1] = source.id .. ': install could not be started.'; end
                    else transfer.errors[#transfer.errors + 1] = source.id .. ': no matching catalog package is available.'; end
                end
            end
        end
        transfer.phase = 'unloading'; transfer.unload_queue = { };
        for _, item in ipairs(transfer.entries) do
            if item.settings[1] and state.installed[item.source.id] ~= nil then
                transfer.unload_queue[#transfer.unload_queue + 1] = item;
            end
        end
    end
    if transfer.phase == 'unloading' then
        if transfer.unload_current ~= nil then
            if is_addon_loaded(transfer.unload_current.source.id) == true then
                transfer.unload_current.skipSettings = true;
                transfer.errors[#transfer.errors + 1] = transfer.unload_current.source.id .. ': could not unload; settings skipped.';
            end
            transfer.unload_current = nil;
        end
        while #transfer.unload_queue > 0 do
            local item = table.remove(transfer.unload_queue, 1);
            if is_addon_loaded(item.source.id) == true then
                transfer.unload_current = item; set_addon_loaded(item.source.id, false, false); return;
            end
        end
        transfer.phase = 'restoring'; transfer.restore_index = 1;
    end
    if transfer.phase == 'restoring' then
        while transfer.restore_index <= #transfer.entries do
            local item = transfer.entries[transfer.restore_index]; transfer.restore_index = transfer.restore_index + 1;
            if item.settings[1] and not item.skipSettings and state.installed[item.source.id] ~= nil then
                local job, err = backend.start({ operation = 'restoreProfileSettings', packageId = item.source.id,
                    stagingPath = transfer.staging });
                if job ~= nil then
                    state.operation = job; state.operation_context = { kind = 'profile-settings', item = item };
                    return;
                end
                transfer.errors[#transfer.errors + 1] = item.source.id .. ': ' .. tostring(err);
            end
        end
        for _, item in ipairs(transfer.entries) do
            if item.sourceMismatch or state.installed[item.source.id] == nil then item.source.autoLoad = false; end
        end
        local profile, err = profiles.import_profile(state, transfer.manifest);
        if profile == nil then transfer.errors[#transfer.errors + 1] = err;
        else save_state(); transfer.imported_name = profile.name; end
        transfer.phase = 'cleanup';
        if transfer.staging ~= nil then
            local job = backend.start({ operation = 'discardProfileImport', packageId = 'profile-transfer', stagingPath = transfer.staging });
            if job ~= nil then state.operation = job; state.operation_context = { kind = 'profile-cleanup' }; return; end
        end
        transfer.phase = 'summary';
        state.notice = (transfer.catalog_profile ~= nil and 'Installed profile ' or 'Imported profile ')
            .. tostring(transfer.imported_name or '') .. '.';
    end
end

local function begin_startup()
    local startup = state.startup;
    startup.started = true; startup.completed = false; startup.queue = { };
    startup.loaded = 0; startup.already_loaded = 0; startup.failures = { }; startup.summary = nil;
    local profile = profiles.active(state);
    startup.profile_name = profile and profile.name or 'Default';
    for _, entry in ipairs(profile and profile.addons or { }) do
        if entry.autoLoad == true and entry.id ~= 'vanahub' then
            local installed = state.installed[entry.id];
            if installed == nil or not is_safe_package_id(entry.id)
                or not ashita.fs.exists(install_root .. entry.id .. '\\.vanahub-owned') then
                startup.failures[#startup.failures + 1] = entry.id .. ' is not installed by VanaHub.';
            elseif state.revocations[installed.sha256] ~= nil then
                startup.failures[#startup.failures + 1] = entry.id .. ' was skipped because its installed artifact is revoked.';
            else startup.queue[#startup.queue + 1] = entry.id; end
        end
    end
    startup.total = #startup.queue + #startup.failures;
end

local function tick_startup()
    local startup = state.startup;
    if not startup.ready then return; end
    if not startup.started then begin_startup(); end
    if startup.completed or state.addon_action ~= nil then return; end
    while #startup.queue > 0 do
        local package_id = table.remove(startup.queue, 1);
        if is_addon_loaded(package_id) == true then startup.already_loaded = startup.already_loaded + 1;
        else set_addon_loaded(package_id, true, true); return; end
    end
    startup.completed = true;
    local summary = 'Auto-load profile ' .. startup.profile_name .. ': ' .. tostring(startup.loaded)
        .. ' loaded, ' .. tostring(startup.already_loaded) .. ' already loaded, '
        .. tostring(#startup.failures) .. ' failed or skipped.';
    startup.summary = summary;
    state.notice = summary;
    print(chat.header('VanaHub'):append(#startup.failures > 0 and chat.error(summary) or chat.message(summary)));
    for _, failure in ipairs(startup.failures) do
        print(chat.header('VanaHub'):append(chat.error(failure)));
    end
end

local function load_texture(path)
    local device = d3d8.get_device();
    if device == nil then return nil; end
    local output = ffi.new('IDirect3DTexture8*[1]');
    if ffi.C.D3DXCreateTextureFromFileA(device, path, output) ~= ffi.C.S_OK then return nil; end
    local image = ffi.cast('IDirect3DTexture8*', output[0]);
    local _, description = image:GetLevelDesc(0);
    if description == nil then image:Release(); return nil; end
    return { image = image, width = tonumber(description.Width), height = tonumber(description.Height) };
end

local function release_textures()
    for _, value in pairs(state.media.cache) do
        if type(value) == 'table' and value.image ~= nil then
            value.image:Release(); value.image = nil;
        end
    end
end

local function request_media(package, url)
    if type(url) ~= 'string' or state.media.cache[url] ~= nil then return; end
    if package._repository == nil or package._repository.builtin ~= true then
        state.media.cache[url] = false; return;
    end
    local digest, extension = url:match('/([a-f0-9]+)%.([A-Za-z]+)$');
    extension = extension and extension:lower() or nil;
    if digest == nil or #digest ~= 64
        or (extension ~= 'jpg' and extension ~= 'jpeg' and extension ~= 'png') then
        state.media.cache[url] = false; return;
    end
    state.media.cache[url] = 'queued';
    state.media.queue[#state.media.queue + 1] = {
        packageId = package.id, url = url, sha256 = digest, extension = extension,
    };
end

local function get_media(package, url)
    request_media(package, url);
    local value = state.media.cache[url];
    return type(value) == 'table' and value or nil, value == false;
end

local function tick_media()
    local media = state.media;
    if media.job ~= nil then
        backend.poll(media.job);
        if media.job.terminal then
            if media.job.result == 0 then media.cache[media.request.url] = load_texture(media.job.message) or false;
            else media.cache[media.request.url] = false; end
            backend.release(media.job); media.job = nil; media.request = nil;
        end
    end
    if media.job == nil and #media.queue > 0 and backend.available then
        local request = table.remove(media.queue, 1);
        local job = backend.start({
            operation = 'fetchMedia', packageId = request.packageId, url = request.url,
            sha256 = request.sha256, extension = request.extension, allowLocal = false,
        });
        if job == nil then media.cache[request.url] = false;
        else media.cache[request.url] = 'loading'; media.job = job; media.request = request; end
    end
end

local function draw_icon(package, size)
    local texture = get_media(package, package.iconUrl);
    local x, y = imgui.GetCursorScreenPos();
    local draw_list = imgui.GetWindowDrawList();
    if texture ~= nil then
        local scale = math.min(size / texture.width, size / texture.height);
        local width, height = texture.width * scale, texture.height * scale;
        local left, top = x + (size - width) / 2, y + (size - height) / 2;
        draw_list:AddImage(tonumber(ffi.cast('uint32_t', texture.image)),
            { left, top }, { left + width, top + height }, { 0, 0 }, { 1, 1 }, 0xFFFFFFFF);
    else
        draw_list:AddRectFilled({ x, y }, { x + size, y + size }, 0xFF454545, 4.0);
        draw_list:AddText({ x + size * 0.38, y + size * 0.2 }, 0xFFD0D0D0, '?');
    end
    imgui.Dummy({ size, size });
end

local function draw_screenshots(package)
    if type(package.screenshots) ~= 'table' or #package.screenshots == 0 then return; end
    imgui.Separator(); imgui.Text('Screenshots');
    for index, url in ipairs(package.screenshots) do
        local texture, failed = get_media(package, url);
        if texture ~= nil then
            local available_width = imgui.GetContentRegionAvail();
            local scale = math.min(1.0, available_width / texture.width, 260 / texture.height);
            imgui.Image(tonumber(ffi.cast('uint32_t', texture.image)),
                { math.floor(texture.width * scale), math.floor(texture.height * scale) });
        elseif failed then imgui.TextDisabled('Screenshot ' .. tostring(index) .. ' is unavailable.');
        else imgui.TextDisabled('Loading screenshot ' .. tostring(index) .. '...'); end
    end
end

local function complete_operation()
    local context = state.operation_context;
    local followup = nil;
    if state.operation.result == 0 and context ~= nil then
        if context.kind == 'repository-cache' then
            if load_repository(context.repository, state.operation.message) then context.repository.status = 'cached'; end
            followup = context.repository;
        elseif context.kind == 'repository' then
            if load_repository(context.repository, state.operation.message) then
                context.repository.status = 'current';
                state.notice = nil;
            end
        elseif context.kind == 'profile-inspect' then
            load_import_review(state.operation.message, nil, nil);
            state.notice = 'Review the imported profile before making changes.';
        elseif context.kind == 'catalog-profile-inspect' then
            load_import_review(state.operation.message, nil, context.profile);
            state.notice = 'Review the downloaded profile before making changes.';
        elseif context.kind == 'profile-export' then
            state.transfer = { mode = nil };
            state.notice = 'Profile exported to ' .. state.operation.message;
        elseif context.kind == 'profile-settings' then
            state.notice = context.item.source.id .. ' settings restored.';
        elseif context.kind == 'profile-cleanup' then
            state.transfer.phase = 'summary';
            state.notice = 'Imported profile ' .. tostring(state.transfer.imported_name or '') .. '.';
        elseif context.kind == 'profile-cancel' then
            state.transfer = { mode = nil }; state.notice = 'Profile import cancelled.';
        elseif context.kind == 'install' then
            local package = context.package;
            state.installed[package.id] = {
                id = package.id, name = package.name, version = package.version,
                sha256 = package.sha256, source = package._repository.id,
            };
            profiles.add_installed(state, package.id, context.transfer ~= true);
            save_state();
            if package.id == 'vanahub' then state.notice = 'Package manager update staged; it will activate on the next Ashita launch.';
            else state.notice = (package.name or package.id) .. ' installed. Select Load to use it now.'; end
        elseif context.kind == 'uninstall' then
            state.installed[context.packageId] = nil;
            profiles.remove_installed(state, context.packageId);
            save_state();
            state.notice = context.packageId .. ' uninstalled; user data was preserved.';
        end
    elseif context ~= nil and context.kind == 'repository-cache' then
        followup = context.repository;
    elseif context ~= nil and context.kind == 'repository' and context.repository.loaded then
        context.repository.status = 'cached (stale)';
        state.notice = 'Using cached catalog; refresh failed: ' .. tostring(state.operation.message);
    elseif state.operation.result ~= 0 then
        if context ~= nil and (context.kind == 'profile-inspect' or context.kind == 'catalog-profile-inspect') then
            state.transfer = { mode = nil };
        elseif context ~= nil and context.kind == 'install' and context.transfer == true
            and state.transfer.mode == 'import' then
            state.transfer.errors[#state.transfer.errors + 1] = context.package.id .. ': '
                .. (state.operation.message ~= '' and state.operation.message or 'install failed.');
        elseif context ~= nil and context.kind == 'profile-settings' and state.transfer.mode == 'import' then
            state.transfer.errors[#state.transfer.errors + 1] = context.item.source.id .. ': '
                .. (state.operation.message ~= '' and state.operation.message or 'settings restore failed.');
        elseif context ~= nil and context.kind == 'profile-cleanup' and state.transfer.mode == 'import' then
            state.transfer.errors[#state.transfer.errors + 1] = 'Temporary import files could not be removed.';
            state.transfer.phase = 'summary';
        elseif context ~= nil and context.kind == 'profile-cancel' then state.transfer = { mode = nil };
        end
        if context ~= nil and context.kind == 'repository' then context.repository.status = 'unavailable'; end
        state.notice = state.operation.message ~= '' and state.operation.message
            or ('Operation failed with result code ' .. tostring(state.operation.result) .. '.');
        print(chat.header('VanaHub'):append(chat.error(state.notice)));
    end
    if context ~= nil and context.kind == 'repository-cache' then state.startup.ready = true; end
    backend.release(state.operation); state.operation = nil; state.operation_context = nil;
    if followup ~= nil then start_repository_refresh(followup); end
end

local function tick_operation()
    if state.operation == nil then return; end
    backend.poll(state.operation);
    if state.operation.terminal then complete_operation(); end
end

local function print_help()
    print(chat.header('VanaHub'):append(chat.message('Commands: /vanahub, /vanahub show, /vanahub hide')));
end

ashita.events.register('command', 'vanahub_command', function (e)
    local args = e.command:args();
    if (#args == 0 or not args[1]:ieq('/vanahub')) then return; end
    e.blocked = true;
    if (#args == 1) then state.visible[1] = not state.visible[1]; return; end
    if (args[2]:ieq('show')) then state.visible[1] = true; return; end
    if (args[2]:ieq('hide')) then state.visible[1] = false; return; end
    print_help();
end);

local function draw_engine_status()
    if not backend.available then
        imgui.TextColored({ 1.0, 0.45, 0.35, 1.0 }, 'Native engine unavailable');
        imgui.TextWrapped(backend.error or 'Build and deploy vanahub_engine.dll.'); return;
    end
    imgui.TextColored({ 0.35, 0.85, 0.45, 1.0 }, 'Native engine ready');
    imgui.TextWrapped('Install location: ' .. install_root);
    if state.operation ~= nil then
        imgui.Separator();
        imgui.Text('Operation: ' .. tostring(state.operation.phase));
        if state.operation.message ~= '' then imgui.TextWrapped(state.operation.message); end
        if imgui.Button('Cancel') then backend.cancel(state.operation); end
    end
end

local category_labels = {
    combat = 'Combat', jobs = 'Jobs', inventory = 'Inventory', crafting = 'Crafting', economy = 'Economy',
    ['maps-travel'] = 'Maps & Travel', ['user-interface'] = 'User Interface',
    ['chat-communication'] = 'Chat & Communication', ['data-tracking'] = 'Data & Tracking',
    ['quality-of-life'] = 'Quality of Life', ['development-tools'] = 'Development Tools',
};

local function package_matches(package)
    local query = (state.search[1] or ''):lower();
    if query == '' then return true; end
    if (package.name or package.id):lower():find(query, 1, true) ~= nil
        or (package.description or ''):lower():find(query, 1, true) ~= nil then return true; end
    if type(package.categories) == 'table' then
        for _, category in ipairs(package.categories) do
            local label = category_labels[category] or tostring(category);
            if label:lower():find(query, 1, true) ~= nil then return true; end
        end
    end
    return false;
end

local function draw_package_details(package)
    imgui.Text(package.name or package.id); imgui.Separator(); imgui.TextWrapped(package.description or '');
    imgui.Text('Version: ' .. tostring(package.version)); imgui.Text('Author: ' .. tostring(package.author));
    imgui.Text('Source: ' .. tostring(package._repository.name));
    if package._repository.builtin then
        imgui.TextColored({ 0.35, 0.75, 1.0, 1.0 }, 'Screened: automated restricted-profile checks passed.');
    else
        imgui.TextColored({ 1.0, 0.65, 0.2, 1.0 }, 'Custom source: not trusted by the built-in repository.');
    end
    if type(package.categories) == 'table' then
        local labels = {};
        for _, category in ipairs(package.categories) do
            table.insert(labels, category_labels[category] or tostring(category));
        end
        imgui.TextWrapped('Categories: ' .. table.concat(labels, ', '));
    end
    if type(package.declaredCapabilities) == 'table' then
        imgui.TextWrapped('Technical access: ' .. table.concat(package.declaredCapabilities, ', '));
    end
    if package._revocation ~= nil then
        imgui.TextColored({ 1.0, 0.25, 0.2, 1.0 }, 'REVOKED: ' .. tostring(package._revocation.reason));
    end
    local startup_busy = state.startup.started and not state.startup.completed;
    local busy = state.operation ~= nil or state.addon_action ~= nil or startup_busy;
    imgui.Separator(); if busy then imgui.BeginDisabled(true); end
    if package._revocation ~= nil and not busy then imgui.BeginDisabled(true); end
    local installed = state.installed[package.id];
    if installed ~= nil then
        local loaded = is_addon_loaded(package.id) == true;
        if package.id ~= 'vanahub' and imgui.Button(loaded and 'Unload' or 'Load') then
            set_addon_loaded(package.id, not loaded, false);
        end
        if package.id ~= 'vanahub' then imgui.SameLine(); end
        if imgui.Button('Uninstall') then start_uninstall(package.id); end
        if installed.sha256 ~= package.sha256 then
            imgui.SameLine();
            if imgui.Button('Update') then start_install(package, package._repository.builtin ~= true); end
        end
        if package.id ~= 'vanahub' then
            imgui.TextColored(loaded and { 0.35, 0.85, 0.45, 1.0 } or { 0.65, 0.65, 0.65, 1.0 },
                loaded and 'Loaded' or 'Not loaded');
        end
    elseif package._repository.builtin then
        if imgui.Button('Install') then start_install(package, false); end
    elseif state.consent_package == package.sha256 then
        if imgui.Button('Install custom artifact') then start_install(package, true); state.consent_package = nil; end
        imgui.SameLine(); if imgui.Button('Cancel consent') then state.consent_package = nil; end
    elseif imgui.Button('Review custom-source warning') then state.consent_package = package.sha256; end
    if busy then imgui.EndDisabled(); end
    if package._revocation ~= nil and not busy then imgui.EndDisabled(); end
    if state.consent_package == package.sha256 then
        imgui.TextWrapped('Confirming permits this exact SHA-256 to use capabilities rejected by the built-in catalog. Structural ZIP hazards remain blocked.');
    end
    if state.operation ~= nil and state.operation_context ~= nil
        and state.operation_context.package == package then
        imgui.Separator();
        imgui.Text('Install status: ' .. tostring(state.operation.phase));
        if state.operation.message ~= '' then imgui.TextWrapped(state.operation.message); end
    elseif state.operation ~= nil then
        imgui.TextDisabled('Install controls are waiting for the current operation to finish.');
    end
    draw_screenshots(package);
end

local function draw_browse()
    imgui.SetNextItemWidth(-1); imgui.InputTextWithHint('##search', 'Search addons...', state.search, 256);
    imgui.Separator();
    imgui.BeginChild('package-list', { 260, 0 }, ImGuiChildFlags_Borders, ImGuiWindowFlags_None);
    for _, package in ipairs(state.packages) do
        local label = package.name or package.id;
        if state.installed[package.id] ~= nil and package.id ~= 'vanahub' then
            label = label .. (is_addon_loaded(package.id) == true and '  [Loaded]' or '  [Not loaded]');
        end
        if package_matches(package) then
            draw_icon(package, 30); imgui.SameLine();
            if imgui.Selectable(label .. '##' .. package.id .. package._repository.id,
                state.selected == package, ImGuiSelectableFlags_None, { 0, 30 }) then state.selected = package; end
        end
    end
    if #state.packages == 0 then imgui.TextDisabled('No catalog loaded.'); end
    imgui.EndChild(); imgui.SameLine();
    imgui.BeginChild('package-detail', { 0, 0 }, ImGuiChildFlags_Borders, ImGuiWindowFlags_None);
    if state.selected ~= nil then draw_package_details(state.selected); else imgui.TextDisabled('Select an addon.'); end
    imgui.EndChild();
end

local function startup_busy()
    return state.startup.started and not state.startup.completed;
end

local function begin_profile_editor(mode, value)
    state.profile_editor = mode;
    state.profile_name[1] = value or '';
    state.confirm_delete_profile = nil;
end

local function draw_profile_controls(busy)
    local active = profiles.active(state);
    if busy then imgui.BeginDisabled(true); end
    imgui.SetNextItemWidth(220);
    if imgui.BeginCombo('Profile', active and active.name or 'Default') then
        for _, profile in ipairs(state.profiles) do
            local selected = profile.id == state.activeProfileId;
            if imgui.Selectable(profile.name .. '##profile-' .. profile.id, selected) then
                state.activeProfileId = profile.id;
                state.profile_editor = nil; state.confirm_delete_profile = nil; save_state();
            end
            if selected then imgui.SetItemDefaultFocus(); end
        end
        imgui.EndCombo();
    end
    imgui.SameLine();
    if imgui.SmallButton('New') then begin_profile_editor('create', 'New Profile'); end
    imgui.SameLine();
    if imgui.SmallButton('Rename') then begin_profile_editor('rename', active and active.name or ''); end
    imgui.SameLine();
    if imgui.SmallButton('Duplicate') then
        profiles.add(state, (active and active.name or 'Profile') .. ' Copy', true); save_state();
    end
    imgui.SameLine();
    if state.confirm_delete_profile == state.activeProfileId then
        if imgui.SmallButton('Confirm delete') then
            local ok, err = profiles.remove(state, state.activeProfileId);
            if not ok then state.notice = err; else save_state(); end
            state.confirm_delete_profile = nil;
        end
        imgui.SameLine();
        if imgui.SmallButton('Cancel') then state.confirm_delete_profile = nil; end
    elseif imgui.SmallButton('Delete') then state.confirm_delete_profile = state.activeProfileId; end
    imgui.SameLine();
    if state.transfer.mode == nil and imgui.SmallButton('Export') then begin_profile_export(); end
    imgui.SameLine();
    if state.transfer.mode == nil and imgui.SmallButton('Import') then begin_profile_import(); end
    if state.profile_editor ~= nil then
        imgui.SetNextItemWidth(220); imgui.InputText('Name##profile-name', state.profile_name, 80);
        imgui.SameLine();
        if imgui.SmallButton('Save##profile-name') then
            if state.profile_editor == 'create' then
                profiles.add(state, state.profile_name[1], false); save_state(); state.profile_editor = nil;
            else
                local ok, err = profiles.rename(state, state.activeProfileId, state.profile_name[1]);
                if ok then save_state(); state.profile_editor = nil; else state.notice = err; end
            end
        end
        imgui.SameLine();
        if imgui.SmallButton('Cancel##profile-name') then state.profile_editor = nil; end
    end
    if busy then imgui.EndDisabled(); end
end

local function cancel_profile_import()
    if state.transfer.staging == nil then state.transfer = { mode = nil }; return; end
    local job, err = backend.start({ operation = 'discardProfileImport', packageId = 'profile-transfer',
        stagingPath = state.transfer.staging });
    if job == nil then state.notice = err; return; end
    state.operation = job; state.operation_context = { kind = 'profile-cancel' };
end

local function draw_profile_transfer()
    local transfer = state.transfer;
    if transfer.mode == 'export' then
        imgui.Separator(); imgui.Text('Export active profile');
        imgui.TextWrapped('Settings are scanned by content. Executables, scripts, nested archives, unsafe Lua, and unrecognized binary files are rejected. Review profiles before sharing; text settings can contain private values.');
        imgui.SetNextItemWidth(360);
        if imgui.InputText('Filename##profile-export', transfer.filename, 161) then transfer.confirm_overwrite = nil; end
        imgui.TextWrapped('Export folder: ' .. profile_export_root);
        for id, selected in pairs(transfer.include) do imgui.Checkbox('Include settings: ' .. id .. '##export-' .. id, selected); end
        if imgui.Button(transfer.confirm_overwrite ~= nil and 'Confirm overwrite' or 'Export profile') then start_profile_export(); end
        imgui.SameLine(); if imgui.Button('Cancel export') then state.transfer = { mode = nil }; end
    elseif transfer.mode == 'import' and transfer.phase == 'choose' then
        imgui.Separator(); imgui.Text('Import profile');
        imgui.TextWrapped('Paste the full path to a .vanahub-profile.zip file. If you copy it into the managed import folder, enter only its filename.');
        imgui.SetNextItemWidth(-1); imgui.InputText('File path##profile-import', transfer.input_path, 4096);
        imgui.TextWrapped('Import folder: ' .. profile_import_root);
        if imgui.Button('Inspect profile') then start_profile_import(); end
        imgui.SameLine(); if imgui.Button('Cancel import') then state.transfer = { mode = nil }; end
    elseif transfer.mode == 'import' and transfer.phase == 'review' then
        imgui.Separator(); imgui.Text((transfer.catalog_profile ~= nil and 'Install ' or 'Import ')
            .. transfer.manifest.profile.name);
        if transfer.catalog_profile ~= nil then
            imgui.TextWrapped('Review the addons and settings below. The downloaded archive passed hash, structural, content, and restricted-Lua scanning. Existing settings will be backed up before replacement.');
        else
            imgui.TextWrapped('Profile settings are untrusted data and may be interpreted by addons. The archive passed structural, content, and restricted-Lua scanning. Existing settings will be backed up and replaced; loaded affected addons will be unloaded.');
        end
        local has_repositories = false;
        for _, repository in pairs(transfer.repositories) do
            has_repositories = true;
            if repository.existing ~= nil then imgui.TextColored({ 0.35, 0.85, 0.45, 1.0 }, 'Configured source: ' .. repository.url);
            else imgui.Checkbox('Trust custom repository: ' .. repository.url, repository.approved); end
        end
        if has_repositories then imgui.Separator(); end
        for _, item in ipairs(transfer.entries) do
            local source, installed = item.source, state.installed[item.source.id];
            imgui.Text(source.id .. (source.version and ('  exported ' .. source.version) or ''));
            imgui.SameLine();
            if installed ~= nil then imgui.TextColored({ 0.35, 0.85, 0.45, 1.0 }, 'Installed ' .. tostring(installed.version));
            else imgui.Checkbox('Install##import-' .. source.id, item.install); end
            if item.sourceMismatch then imgui.SameLine(); imgui.TextColored({ 1.0, 0.45, 0.35, 1.0 }, 'Different source; settings disabled'); end
            if source.settings == true then imgui.SameLine(); imgui.Checkbox('Restore settings##import-' .. source.id, item.settings); end
        end
        local confirm_label = transfer.catalog_profile ~= nil and 'Install selected addons and profile'
            or 'Import selected addons and settings';
        if imgui.Button(confirm_label) then confirm_profile_import(); end
        imgui.SameLine();
        if imgui.Button(transfer.catalog_profile ~= nil and 'Cancel install' or 'Cancel import') then
            cancel_profile_import();
        end
    elseif transfer.mode == 'import' and transfer.phase == 'summary' then
        imgui.Separator(); imgui.Text(transfer.catalog_profile ~= nil and 'Profile installed' or 'Import complete');
        if transfer.imported_name ~= nil then imgui.Text('Active profile: ' .. transfer.imported_name); end
        for _, message in ipairs(transfer.errors or { }) do imgui.TextWrapped(message); end
        if #(transfer.errors or { }) == 0 then
            imgui.TextColored({ 0.35, 0.85, 0.45, 1.0 }, transfer.catalog_profile ~= nil
                and 'All selected items were installed.' or 'All selected items were imported.');
        end
        if imgui.Button('Done##profile-import') then state.transfer = { mode = nil }; end
    elseif transfer.mode == 'import' then
        imgui.Separator(); imgui.Text((transfer.catalog_profile ~= nil and 'Profile install: ' or 'Profile import: ')
            .. tostring(transfer.phase));
        if state.operation ~= nil and state.operation.message ~= '' then imgui.TextWrapped(state.operation.message); end
    end
end

local function catalog_profile_matches(profile)
    local query = (state.profile_search[1] or ''):lower();
    if query == '' then return true; end
    if (profile.name or profile.id):lower():find(query, 1, true) ~= nil
        or (profile.description or ''):lower():find(query, 1, true) ~= nil
        or (profile.author or ''):lower():find(query, 1, true) ~= nil then return true; end
    if type(profile.categories) == 'table' then
        for _, category in ipairs(profile.categories) do
            local label = category_labels[category] or tostring(category);
            if label:lower():find(query, 1, true) ~= nil then return true; end
        end
    end
    for _, entry in ipairs(profile.addons or { }) do
        if entry.id:lower():find(query, 1, true) ~= nil then return true; end
    end
    return false;
end

local function draw_catalog_profile_details(profile)
    imgui.Text(profile.name or profile.id); imgui.Separator();
    imgui.TextWrapped(profile.description or '');
    imgui.Text('Author: ' .. tostring(profile.author));
    imgui.Text('Source: ' .. tostring(profile._repository.name));
    if profile._repository.builtin then
        imgui.TextColored({ 0.35, 0.75, 1.0, 1.0 }, 'Signed built-in catalog profile');
    else
        imgui.TextColored({ 1.0, 0.65, 0.2, 1.0 }, 'Custom catalog profile');
    end
    if type(profile.categories) == 'table' then
        local labels = { };
        for _, category in ipairs(profile.categories) do
            labels[#labels + 1] = category_labels[category] or tostring(category);
        end
        imgui.TextWrapped('Categories: ' .. table.concat(labels, ', '));
    end
    imgui.Separator(); imgui.Text('Addons (' .. tostring(#profile.addons) .. ')');
    for _, entry in ipairs(profile.addons) do
        local installed = state.installed[entry.id] ~= nil;
        local source = { id = entry.id, source = profile._repository.builtin and { builtin = true }
            or { builtin = false, url = profile._repository.url } };
        local available = installed or package_for_import(source) ~= nil;
        local color = installed and { 0.35, 0.85, 0.45, 1.0 }
            or (available and { 0.35, 0.75, 1.0, 1.0 } or { 1.0, 0.45, 0.35, 1.0 });
        local status = installed and 'Installed' or (available and 'Available' or 'Unavailable');
        imgui.TextColored(color, entry.id .. '  ' .. status
            .. (entry.autoLoad and '  [Auto-load]' or ''));
    end
    local busy = state.operation ~= nil or state.addon_action ~= nil or startup_busy()
        or (state.transfer.mode ~= nil and state.transfer.phase ~= 'summary');
    imgui.Separator();
    if busy then imgui.BeginDisabled(true); end
    if imgui.Button('Install profile') then begin_catalog_profile_import(profile); end
    if busy then imgui.EndDisabled(); end
    draw_screenshots(profile);
end

local function draw_catalog_profiles()
    if state.transfer.mode == 'import' and state.transfer.catalog_profile ~= nil then
        draw_profile_transfer(); return;
    end
    imgui.SetNextItemWidth(-1);
    imgui.InputTextWithHint('##profile-search', 'Search profiles...', state.profile_search, 256);
    imgui.Separator();
    imgui.BeginChild('catalog-profile-list', { 260, 0 }, ImGuiChildFlags_Borders, ImGuiWindowFlags_None);
    local visible = 0;
    for _, profile in ipairs(state.catalog_profiles) do
        if catalog_profile_matches(profile) then
            visible = visible + 1; draw_icon(profile, 30); imgui.SameLine();
            if imgui.Selectable((profile.name or profile.id) .. '##catalog-profile-' .. profile.id
                .. profile._repository.id, state.selected_catalog_profile == profile,
                ImGuiSelectableFlags_None, { 0, 30 }) then state.selected_catalog_profile = profile; end
        end
    end
    if #state.catalog_profiles == 0 then imgui.TextDisabled('No profiles are available in the current catalogs.');
    elseif visible == 0 then imgui.TextDisabled('No profiles match your search.'); end
    imgui.EndChild(); imgui.SameLine();
    imgui.BeginChild('catalog-profile-detail', { 0, 0 }, ImGuiChildFlags_Borders, ImGuiWindowFlags_None);
    if state.selected_catalog_profile ~= nil then draw_catalog_profile_details(state.selected_catalog_profile);
    else imgui.TextDisabled('Select a profile.'); end
    imgui.EndChild();
end

local function draw_installed()
    local busy = state.operation ~= nil or state.addon_action ~= nil or startup_busy()
        or (state.transfer.mode ~= nil and state.transfer.phase ~= 'summary');
    draw_profile_controls(busy);
    draw_profile_transfer();
    imgui.TextDisabled('Auto-load and order apply the next time VanaHub starts.');
    if state.startup.started and not state.startup.completed then
        local processed = state.startup.loaded + state.startup.already_loaded + #state.startup.failures;
        imgui.Text('Auto-loading ' .. state.startup.profile_name .. ': ' .. tostring(processed)
            .. ' / ' .. tostring(state.startup.total));
    elseif state.startup.summary ~= nil then imgui.TextWrapped(state.startup.summary); end
    imgui.Separator();
    local profile = profiles.active(state);
    local any = false;
    for index, entry in ipairs(profile and profile.addons or { }) do
        local id, package = entry.id, state.installed[entry.id];
        if package ~= nil then
            any = true;
            if busy or index == 1 then imgui.BeginDisabled(true); end
            if imgui.ArrowButton('up##' .. id, ImGuiDir_Up) then profiles.move(profile, index, -1); save_state(); end
            if busy or index == 1 then imgui.EndDisabled(); end
            imgui.SameLine();
            if busy or index == #profile.addons then imgui.BeginDisabled(true); end
            if imgui.ArrowButton('down##' .. id, ImGuiDir_Down) then profiles.move(profile, index, 1); save_state(); end
            if busy or index == #profile.addons then imgui.EndDisabled(); end
            imgui.SameLine();
            local auto_load = T{ entry.autoLoad == true };
            if busy or id == 'vanahub' then imgui.BeginDisabled(true); end
            if imgui.Checkbox('Auto-load##' .. id, auto_load) then entry.autoLoad = auto_load[1] == true; save_state(); end
            if busy or id == 'vanahub' then imgui.EndDisabled(); end
            imgui.SameLine();
            imgui.Text((package.name or id) .. '  ' .. tostring(package.version)); imgui.SameLine();
            local loaded = is_addon_loaded(id) == true;
            if id ~= 'vanahub' then
                imgui.TextColored(loaded and { 0.35, 0.85, 0.45, 1.0 } or { 0.65, 0.65, 0.65, 1.0 },
                    loaded and 'Loaded' or 'Not loaded');
                imgui.SameLine();
            end
            local revocation = state.revocations[package.sha256];
            if revocation ~= nil then
                imgui.TextColored({ 1.0, 0.25, 0.2, 1.0 }, 'REVOKED: ' .. tostring(revocation.reason));
            end
            if busy then imgui.BeginDisabled(true); end
            if id ~= 'vanahub' and imgui.SmallButton((loaded and 'Unload##' or 'Load##') .. id) then
                set_addon_loaded(id, not loaded, false);
            end
            if id ~= 'vanahub' then imgui.SameLine(); end
            if imgui.SmallButton('Uninstall##' .. id) then start_uninstall(id); end
            if busy then imgui.EndDisabled(); end
        end
    end
    if not any then imgui.TextDisabled('No managed addons are installed.'); end
    imgui.Separator(); imgui.TextDisabled('Uninstall preserves configuration and untracked files.');
end

local function draw_repositories()
    for _, repository in ipairs(state.repositories) do
        imgui.Text(repository.name); imgui.SameLine();
        imgui.TextColored(repository.builtin and { 0.35, 0.75, 1.0, 1.0 } or { 1.0, 0.65, 0.2, 1.0 }, repository.builtin and 'Screened' or 'Custom');
        if repository.status ~= nil then imgui.SameLine(); imgui.TextDisabled(tostring(repository.status)); end
        if repository.generated_at ~= nil then imgui.TextDisabled('Catalog generated: ' .. tostring(repository.generated_at)); end
        if repository.url ~= '' then
            imgui.SameLine();
            if state.operation ~= nil then imgui.BeginDisabled(true); end
            if imgui.SmallButton('Refresh##' .. repository.id) then start_repository_refresh(repository); end
            if state.operation ~= nil then imgui.EndDisabled(); end
        end
    end
    imgui.Separator();
    imgui.TextWrapped('Custom repositories can deliver code that reads files, accesses memory, or invokes native APIs. Add only sources you trust.');
    imgui.InputTextWithHint('##custom-url', 'https://.../index.json', state.custom_url, 1024);
    imgui.Checkbox('I understand that custom addons execute inside FFXI.', state.custom_ack);
    local candidate = state.custom_url[1] or '';
    local is_local = state.developer_mode[1] and (candidate:match('^file:///') ~= nil or candidate:match('^http://localhost[:/]') ~= nil);
    local valid = state.custom_ack[1] and (candidate:match('^https://') ~= nil or is_local);
    if not valid then imgui.BeginDisabled(true); end
    if imgui.Button('Add custom repository') then
        local id = 'custom-' .. tostring(#state.repositories);
        local repository = { id = id, name = candidate, url = candidate, builtin = false, enabled = true, local_source = is_local };
        state.repositories[#state.repositories + 1] = repository; save_state(); start_repository_refresh(repository);
        state.custom_url[1] = ''; state.custom_ack[1] = false;
    end
    if not valid then imgui.EndDisabled(); end
    imgui.Separator(); imgui.Checkbox('Developer mode (local/localhost sources)', state.developer_mode);
    if state.developer_mode[1] then imgui.TextColored({ 1.0, 0.35, 0.25, 1.0 }, 'Developer mode is active. Local sources bypass HTTPS transport protections.'); end
end

ashita.fs.create_directory(config_root);
ashita.fs.create_directory(profile_root);
ashita.fs.create_directory(profile_export_root);
ashita.fs.create_directory(profile_import_root);
load_state();
save_state();
local version_root = addon.path .. 'versions\\' .. (addon.active_version or addon.version or '0.1.0') .. '\\';
backend.initialize(version_root, builtin.public_key);
if backend.available and builtin.index_url ~= '' then start_repository_cache(state.repositories[1]);
else state.startup.ready = true; end

ashita.events.register('d3d_present', 'vanahub_render', function ()
    tick_operation();
    tick_addon_action();
    advance_profile_import();
    tick_startup();
    tick_media();
    if not state.visible[1] then return; end
    imgui.SetNextWindowSize({ 800, 560 }, ImGuiCond_FirstUseEver);
    if imgui.Begin('VanaHub##vanahub', state.visible, bit.bor(ImGuiWindowFlags_MenuBar, ImGuiWindowFlags_NoCollapse)) then
        if state.notice ~= nil then imgui.TextWrapped(state.notice); imgui.Separator(); end
        if imgui.BeginTabBar('##vanahub-tabs') then
            if imgui.BeginTabItem('Browse') then draw_browse(); imgui.EndTabItem(); end
            if imgui.BeginTabItem('Profiles') then draw_catalog_profiles(); imgui.EndTabItem(); end
            if imgui.BeginTabItem('Installed') then draw_installed(); imgui.EndTabItem(); end
            if imgui.BeginTabItem('Repositories') then draw_repositories(); imgui.EndTabItem(); end
            if imgui.BeginTabItem('Status') then draw_engine_status(); imgui.EndTabItem(); end
            imgui.EndTabBar();
        end
    end
    imgui.End();
end);

ashita.events.register('unload', 'vanahub_unload', function ()
    release_textures(); save_state(); backend.shutdown();
end);
print(chat.header('VanaHub'):append(chat.message('Loaded. Use /vanahub to open the addon browser.')));

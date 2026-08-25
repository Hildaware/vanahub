require 'common';

local imgui = require 'imgui';
local chat = require 'chat';
local json = require 'json';
local backend = require 'backend';
local builtin = require 'builtin';

local config_root = AshitaCore:GetInstallPath() .. '\\config\\addons\\vanahub\\';
local state_path = config_root .. 'state.json';
local repository_path = config_root .. 'repositories.json';
local state = {
    visible = T{ false }, search = T{ '' }, selected = nil, packages = { }, installed = { },
    repositories = { }, operation = nil, operation_context = nil, notice = nil,
    revocations = { },
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

local function load_state()
    local installed = decode(read_text(state_path));
    if type(installed) == 'table' then state.installed = installed; end
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
    write_text(state_path, encode(state.installed));
    local custom = { };
    for _, repository in ipairs(state.repositories) do
        if not repository.builtin then custom[#custom + 1] = repository; end
    end
    write_text(repository_path, encode(custom));
end

local function rebuild_packages()
    local selected_id = state.selected and state.selected.id or nil;
    local selected_repository = state.selected and state.selected._repository and state.selected._repository.id or nil;
    local packages = { };
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
                    package._repository = repository; packages[#packages + 1] = package;
                end
            end
        end
    end
    table.sort(packages, function (a, b)
        if a.id == b.id then return a._repository.builtin and not b._repository.builtin; end
        return (a.name or a.id):lower() < (b.name or b.id):lower();
    end);
    state.packages = packages; state.revocations = revocations; state.selected = nil;
    if selected_id ~= nil then
        for _, package in ipairs(packages) do
            if package.id == selected_id and package._repository.id == selected_repository then state.selected = package; break; end
        end
    end
end

local function load_repository(repository, path)
    local document = decode(read_text(path));
    if type(document) ~= 'table' or document.schemaVersion ~= 1 or type(document.packages) ~= 'table' then
        state.notice = 'Repository index is invalid: ' .. tostring(repository.name); return false;
    end
    repository.name = document.repository and document.repository.name or repository.name;
    repository.packages = document.packages; repository.revocations = document.revocations or { };
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
    if job == nil then state.notice = err; start_repository_refresh(repository); return; end
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
end

local function start_uninstall(package_id)
    local job, err = backend.start({ operation = 'uninstall', packageId = package_id });
    if job == nil then state.notice = err; return; end
    state.operation = job; state.operation_context = { kind = 'uninstall', packageId = package_id };
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
        elseif context.kind == 'install' then
            local package = context.package;
            state.installed[package.id] = {
                id = package.id, name = package.name, version = package.version,
                sha256 = package.sha256, source = package._repository.id,
            };
            save_state();
            if package.id == 'vanahub' then state.notice = 'Package manager update staged; it will activate on the next Ashita launch.';
            else state.notice = (package.name or package.id) .. ' installed. Reload it explicitly when ready.'; end
        elseif context.kind == 'uninstall' then
            state.installed[context.packageId] = nil; save_state();
            state.notice = context.packageId .. ' uninstalled; user data was preserved.';
        end
    elseif context ~= nil and context.kind == 'repository-cache' then
        followup = context.repository;
    elseif context ~= nil and context.kind == 'repository' and context.repository.loaded then
        context.repository.status = 'cached (stale)';
        state.notice = 'Using cached catalog; refresh failed: ' .. tostring(state.operation.message);
    elseif state.operation.result ~= 0 then
        if context ~= nil and context.kind == 'repository' then context.repository.status = 'unavailable'; end
        state.notice = state.operation.message;
    end
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
    if state.operation ~= nil then
        imgui.Separator();
        imgui.Text('Operation: ' .. tostring(state.operation.phase));
        if state.operation.message ~= '' then imgui.TextWrapped(state.operation.message); end
        if imgui.Button('Cancel') then backend.cancel(state.operation); end
    end
end

local function package_matches(package)
    local query = (state.search[1] or ''):lower();
    if query == '' then return true; end
    return (package.name or package.id):lower():find(query, 1, true) ~= nil
        or (package.description or ''):lower():find(query, 1, true) ~= nil;
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
    if type(package.declaredCapabilities) == 'table' then
        imgui.TextWrapped('Capabilities: ' .. table.concat(package.declaredCapabilities, ', '));
    end
    if package._revocation ~= nil then
        imgui.TextColored({ 1.0, 0.25, 0.2, 1.0 }, 'REVOKED: ' .. tostring(package._revocation.reason));
    end
    imgui.Separator(); if state.operation ~= nil then imgui.BeginDisabled(true); end
    if package._revocation ~= nil and state.operation == nil then imgui.BeginDisabled(true); end
    if package._repository.builtin then
        if imgui.Button(state.installed[package.id] and 'Update' or 'Install') then start_install(package, false); end
    elseif state.consent_package == package.sha256 then
        if imgui.Button('Install custom artifact') then start_install(package, true); state.consent_package = nil; end
        imgui.SameLine(); if imgui.Button('Cancel consent') then state.consent_package = nil; end
    elseif imgui.Button('Review custom-source warning') then state.consent_package = package.sha256; end
    if state.operation ~= nil then imgui.EndDisabled(); end
    if package._revocation ~= nil and state.operation == nil then imgui.EndDisabled(); end
    if state.consent_package == package.sha256 then
        imgui.TextWrapped('Confirming permits this exact SHA-256 to use capabilities rejected by the built-in catalog. Structural ZIP hazards remain blocked.');
    end
end

local function draw_browse()
    imgui.SetNextItemWidth(-1); imgui.InputTextWithHint('##search', 'Search addons...', state.search, 256);
    imgui.Separator();
    imgui.BeginChild('package-list', { 260, 0 }, ImGuiChildFlags_Borders, ImGuiWindowFlags_None);
    for _, package in ipairs(state.packages) do
        if package_matches(package) and imgui.Selectable((package.name or package.id) .. '##' .. package.id .. package._repository.id, state.selected == package) then state.selected = package; end
    end
    if #state.packages == 0 then imgui.TextDisabled('No catalog loaded.'); end
    imgui.EndChild(); imgui.SameLine();
    imgui.BeginChild('package-detail', { 0, 0 }, ImGuiChildFlags_Borders, ImGuiWindowFlags_None);
    if state.selected ~= nil then draw_package_details(state.selected); else imgui.TextDisabled('Select an addon.'); end
    imgui.EndChild();
end

local function draw_installed()
    local any = false;
    for id, package in pairs(state.installed) do
        any = true; imgui.Text((package.name or id) .. '  ' .. tostring(package.version)); imgui.SameLine();
        local revocation = state.revocations[package.sha256];
        if revocation ~= nil then
            imgui.TextColored({ 1.0, 0.25, 0.2, 1.0 }, 'REVOKED: ' .. tostring(revocation.reason));
        end
        if state.operation ~= nil then imgui.BeginDisabled(true); end
        if imgui.SmallButton('Uninstall##' .. id) then start_uninstall(id); end
        if state.operation ~= nil then imgui.EndDisabled(); end
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
load_state();
local version_root = addon.path .. 'versions\\' .. (addon.active_version or addon.version or '0.1.0') .. '\\';
backend.initialize(version_root, builtin.public_key);
if backend.available and builtin.index_url ~= '' then start_repository_cache(state.repositories[1]); end

ashita.events.register('d3d_present', 'vanahub_render', function ()
    tick_operation();
    if not state.visible[1] then return; end
    imgui.SetNextWindowSize({ 800, 560 }, ImGuiCond_FirstUseEver);
    if imgui.Begin('VanaHub##vanahub', state.visible, bit.bor(ImGuiWindowFlags_MenuBar, ImGuiWindowFlags_NoCollapse)) then
        if state.notice ~= nil then imgui.TextWrapped(state.notice); imgui.Separator(); end
        if imgui.BeginTabBar('##vanahub-tabs') then
            if imgui.BeginTabItem('Browse') then draw_browse(); imgui.EndTabItem(); end
            if imgui.BeginTabItem('Installed') then draw_installed(); imgui.EndTabItem(); end
            if imgui.BeginTabItem('Repositories') then draw_repositories(); imgui.EndTabItem(); end
            if imgui.BeginTabItem('Status') then draw_engine_status(); imgui.EndTabItem(); end
            imgui.EndTabBar();
        end
    end
    imgui.End();
end);

ashita.events.register('unload', 'vanahub_unload', function () save_state(); backend.shutdown(); end);
print(chat.header('VanaHub'):append(chat.message('Loaded. Use /vanahub to open the addon browser.')));

local profiles = { };

local function copy_addons(addons, preserve_auto_load)
    local result = { };
    for _, entry in ipairs(addons or { }) do
        result[#result + 1] = {
            id = entry.id,
            autoLoad = preserve_auto_load and entry.autoLoad == true or false,
            source = entry.source,
            version = entry.version,
            sha256 = entry.sha256,
        };
    end
    return result;
end

local function sorted_installed_ids(installed)
    local ids = { };
    for id, _ in pairs(installed or { }) do ids[#ids + 1] = id; end
    table.sort(ids, function (a, b)
        local left = installed[a] and (installed[a].name or a) or a;
        local right = installed[b] and (installed[b].name or b) or b;
        left, right = tostring(left):lower(), tostring(right):lower();
        if left == right then return a < b; end
        return left < right;
    end);
    return ids;
end

local function safe_id(value)
    return type(value) == 'string' and #value >= 2 and #value <= 64
        and value:match('^[a-z0-9][a-z0-9._-]+$') ~= nil;
end

local function normalize_addons(addons, installed, retain_missing)
    local result, seen = { }, { };
    for _, entry in ipairs(type(addons) == 'table' and addons or { }) do
        local id = type(entry) == 'table' and entry.id or nil;
        if safe_id(id) and (installed[id] ~= nil or retain_missing) and not seen[id] then
            local normalized = {
                id = id,
                autoLoad = installed[id] ~= nil and id ~= 'vanahub' and entry.autoLoad == true,
            };
            if type(entry.version) == 'string' and #entry.version <= 80 then normalized.version = entry.version; end
            if type(entry.sha256) == 'string' and #entry.sha256 == 64
                and entry.sha256:match('^[a-f0-9]+$') ~= nil then normalized.sha256 = entry.sha256; end
            if type(entry.source) == 'table' and type(entry.source.builtin) == 'boolean' then
                if entry.source.builtin == true then normalized.source = { builtin = true };
                elseif type(entry.source.url) == 'string' and #entry.source.url <= 2048
                    and entry.source.url:match('^https://') ~= nil then
                    normalized.source = { builtin = false, url = entry.source.url,
                        name = type(entry.source.name) == 'string' and entry.source.name or nil };
                end
            end
            result[#result + 1] = normalized;
            seen[id] = true;
        end
    end
    for _, id in ipairs(sorted_installed_ids(installed)) do
        if not seen[id] then result[#result + 1] = { id = id, autoLoad = false }; end
    end
    return result;
end

local function unique_name(document, requested)
    local base = tostring(requested or ''):match('^%s*(.-)%s*$');
    if base == '' then base = 'Profile'; end
    local used = { };
    for _, profile in ipairs(document.profiles) do used[profile.name:lower()] = true; end
    if not used[base:lower()] then return base; end
    local index = 2;
    while used[(base .. ' ' .. tostring(index)):lower()] do index = index + 1; end
    return base .. ' ' .. tostring(index);
end

local function next_id(document)
    local used = { };
    for _, profile in ipairs(document.profiles) do used[profile.id] = true; end
    local index = 1;
    while used['profile-' .. tostring(index)] do index = index + 1; end
    return 'profile-' .. tostring(index);
end

function profiles.normalize(raw, installed)
    local document = {
        schemaVersion = 3,
        installed = installed or { },
        profiles = { },
        activeProfileId = nil,
    };
    local source_profiles = type(raw) == 'table' and (raw.schemaVersion == 2 or raw.schemaVersion == 3)
        and type(raw.profiles) == 'table' and raw.profiles or { };
    local retain_missing = type(raw) == 'table' and raw.schemaVersion == 3;
    local used_ids, used_names = { }, { };
    for _, source in ipairs(source_profiles) do
        if type(source) == 'table' then
            local id = type(source.id) == 'string' and source.id or '';
            local name = type(source.name) == 'string' and source.name:match('^%s*(.-)%s*$') or '';
            if id ~= '' and name ~= '' and not used_ids[id] and not used_names[name:lower()] then
                document.profiles[#document.profiles + 1] = {
                    id = id,
                    name = name,
                    addons = normalize_addons(source.addons, document.installed, retain_missing),
                };
                used_ids[id], used_names[name:lower()] = true, true;
            end
        end
    end
    if #document.profiles == 0 then
        local addons = { };
        for _, id in ipairs(sorted_installed_ids(document.installed)) do
            addons[#addons + 1] = { id = id, autoLoad = false };
        end
        document.profiles[1] = { id = 'default', name = 'Default', addons = addons };
    end
    local requested = type(raw) == 'table' and raw.activeProfileId or nil;
    for _, profile in ipairs(document.profiles) do
        if profile.id == requested then document.activeProfileId = requested; break; end
    end
    document.activeProfileId = document.activeProfileId or document.profiles[1].id;
    return document;
end

function profiles.import_profile(document, raw)
    local valid, error = profiles.validate_import(raw);
    if not valid then return nil, error; end
    local source = raw.profile;
    local requested_name = type(source.name) == 'string' and source.name or 'Imported Profile';
    local profile = {
        id = next_id(document),
        name = unique_name(document, requested_name),
        addons = normalize_addons(source.addons, document.installed or { }, true),
    };
    for _, entry in ipairs(profile.addons) do
        if (document.installed or { })[entry.id] == nil then entry.autoLoad = false; end
    end
    document.profiles[#document.profiles + 1] = profile;
    document.activeProfileId = profile.id;
    return profile;
end

function profiles.validate_import(raw)
    if type(raw) ~= 'table' or raw.schemaVersion ~= 1 or type(raw.profile) ~= 'table'
        or type(raw.profile.addons) ~= 'table' or #raw.profile.addons > 256 then
        return false, 'Profile archive manifest is invalid.';
    end
    if type(raw.profile.name) ~= 'string' or raw.profile.name:match('^%s*(.-)%s*$') == ''
        or #raw.profile.name > 80 or raw.profile.name:find('[%z\1-\31]') ~= nil then
        return false, 'Imported profile name is invalid.';
    end
    local seen = { };
    for _, entry in ipairs(raw.profile.addons) do
        if type(entry) ~= 'table' or not safe_id(entry.id) or seen[entry.id] then
            return false, 'Imported profile contains an invalid or duplicate addon id.';
        end
        if type(entry.autoLoad) ~= 'boolean' or type(entry.settings) ~= 'boolean'
            or type(entry.source) ~= 'table' or type(entry.source.builtin) ~= 'boolean' then
            return false, 'Imported addon options are invalid.';
        end
        seen[entry.id] = true;
        if entry.version ~= nil and (type(entry.version) ~= 'string' or #entry.version > 80) then
            return false, 'Imported addon version is invalid.';
        end
        if entry.sha256 ~= nil and (type(entry.sha256) ~= 'string'
            or entry.sha256:match('^[a-f0-9]+$') == nil or #entry.sha256 ~= 64) then
            return false, 'Imported addon hash is invalid.';
        end
        if entry.source.builtin ~= true and (type(entry.source.url) ~= 'string'
            or #entry.source.url > 2048 or entry.source.url:match('^https://') == nil) then
            return false, 'Imported custom repository URL is invalid.';
        end
        if entry.source.name ~= nil and (type(entry.source.name) ~= 'string' or #entry.source.name > 200) then
            return false, 'Imported repository name is invalid.';
        end
    end
    return true;
end

function profiles.validate_catalog(raw)
    if type(raw) ~= 'table' or raw.schemaVersion ~= 1 or not safe_id(raw.id)
        or type(raw.name) ~= 'string' or raw.name:match('^%s*(.-)%s*$') == '' or #raw.name > 80
        or raw.name:find('[%z\1-\31]') ~= nil or type(raw.description) ~= 'string'
        or raw.description == '' or #raw.description > 2000 or type(raw.author) ~= 'string'
        or raw.author == '' or #raw.author > 80 or type(raw.version) ~= 'string'
        or #raw.version > 80 or type(raw.downloadUrl) ~= 'string'
        or raw.downloadUrl:match('^https://github%.com/[^/]+/[^/]+/releases/download/[^/]+/[^/]+$') == nil
        or type(raw.sha256) ~= 'string' or #raw.sha256 ~= 64
        or raw.sha256:match('^[a-f0-9]+$') == nil or type(raw.compressedSize) ~= 'number'
        or raw.compressedSize < 1 or raw.compressedSize > 67108864 or type(raw.addons) ~= 'table'
        or #raw.addons == 0 or #raw.addons > 256 then
        return false, 'Catalog profile manifest is invalid.';
    end
    local seen = { };
    for _, entry in ipairs(raw.addons) do
        if type(entry) ~= 'table' or not safe_id(entry.id) or seen[entry.id]
            or entry.id == 'vanahub' or type(entry.autoLoad) ~= 'boolean'
            or type(entry.settings) ~= 'boolean' or type(entry.source) ~= 'table'
            or type(entry.source.builtin) ~= 'boolean'
            or (entry.source.builtin ~= true and (type(entry.source.url) ~= 'string'
                or entry.source.url:match('^https://') == nil)) then
            return false, 'Catalog profile contains invalid or duplicate addons.';
        end
        seen[entry.id] = true;
    end
    return true;
end

function profiles.catalog_import(raw, repository)
    local valid, error = profiles.validate_catalog(raw);
    if not valid then return nil, error; end
    local manifest = { schemaVersion = 1, profile = { name = raw.name, addons = { } } };
    for _, entry in ipairs(raw.addons) do
        manifest.profile.addons[#manifest.profile.addons + 1] = {
            id = entry.id, autoLoad = entry.autoLoad, settings = false,
            version = entry.version, sha256 = entry.sha256, source = entry.source,
        };
    end
    return manifest;
end

function profiles.active(document)
    for _, profile in ipairs(document.profiles) do
        if profile.id == document.activeProfileId then return profile; end
    end
    return document.profiles[1];
end

function profiles.add(document, requested_name, duplicate)
    local source = profiles.active(document);
    local profile = {
        id = next_id(document),
        name = unique_name(document, requested_name),
        addons = copy_addons(source and source.addons or { }, duplicate == true),
    };
    document.profiles[#document.profiles + 1] = profile;
    document.activeProfileId = profile.id;
    return profile;
end

function profiles.rename(document, profile_id, requested_name)
    local target = nil;
    for _, profile in ipairs(document.profiles) do
        if profile.id == profile_id then target = profile;
        elseif profile.name:lower() == tostring(requested_name or ''):match('^%s*(.-)%s*$'):lower() then
            return false, 'Profile names must be unique.';
        end
    end
    local name = tostring(requested_name or ''):match('^%s*(.-)%s*$');
    if target == nil then return false, 'Profile not found.'; end
    if name == '' then return false, 'Profile name cannot be empty.'; end
    target.name = name;
    return true;
end

function profiles.remove(document, profile_id)
    if #document.profiles <= 1 then return false, 'At least one profile is required.'; end
    for index, profile in ipairs(document.profiles) do
        if profile.id == profile_id then
            table.remove(document.profiles, index);
            if document.activeProfileId == profile_id then
                document.activeProfileId = document.profiles[math.min(index, #document.profiles)].id;
            end
            return true;
        end
    end
    return false, 'Profile not found.';
end

function profiles.add_installed(document, package_id, enable_active)
    if enable_active == nil then enable_active = true; end
    for _, profile in ipairs(document.profiles) do
        local found = false;
        for _, entry in ipairs(profile.addons) do
            if entry.id == package_id then found = true; break; end
        end
        if not found then
            profile.addons[#profile.addons + 1] = {
                id = package_id,
                autoLoad = enable_active and package_id ~= 'vanahub' and profile.id == document.activeProfileId,
            };
        end
    end
end

function profiles.remove_installed(document, package_id)
    for _, profile in ipairs(document.profiles) do
        for index = #profile.addons, 1, -1 do
            if profile.addons[index].id == package_id then table.remove(profile.addons, index); end
        end
    end
end

function profiles.move(profile, index, offset)
    local destination = index + offset;
    if index < 1 or index > #profile.addons or destination < 1 or destination > #profile.addons then return false; end
    profile.addons[index], profile.addons[destination] = profile.addons[destination], profile.addons[index];
    return true;
end

return profiles;

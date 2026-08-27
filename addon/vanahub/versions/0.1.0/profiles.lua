local profiles = { };

local function copy_addons(addons, preserve_auto_load)
    local result = { };
    for _, entry in ipairs(addons or { }) do
        result[#result + 1] = {
            id = entry.id,
            autoLoad = preserve_auto_load and entry.autoLoad == true or false,
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

local function normalize_addons(addons, installed)
    local result, seen = { }, { };
    for _, entry in ipairs(type(addons) == 'table' and addons or { }) do
        local id = type(entry) == 'table' and entry.id or nil;
        if type(id) == 'string' and installed[id] ~= nil and not seen[id] then
            result[#result + 1] = { id = id, autoLoad = id ~= 'vanahub' and entry.autoLoad == true };
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
        schemaVersion = 2,
        installed = installed or { },
        profiles = { },
        activeProfileId = nil,
    };
    local source_profiles = type(raw) == 'table' and raw.schemaVersion == 2
        and type(raw.profiles) == 'table' and raw.profiles or { };
    local used_ids, used_names = { }, { };
    for _, source in ipairs(source_profiles) do
        if type(source) == 'table' then
            local id = type(source.id) == 'string' and source.id or '';
            local name = type(source.name) == 'string' and source.name:match('^%s*(.-)%s*$') or '';
            if id ~= '' and name ~= '' and not used_ids[id] and not used_names[name:lower()] then
                document.profiles[#document.profiles + 1] = {
                    id = id,
                    name = name,
                    addons = normalize_addons(source.addons, document.installed),
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

function profiles.add_installed(document, package_id)
    for _, profile in ipairs(document.profiles) do
        local found = false;
        for _, entry in ipairs(profile.addons) do
            if entry.id == package_id then found = true; break; end
        end
        if not found then
            profile.addons[#profile.addons + 1] = {
                id = package_id,
                autoLoad = package_id ~= 'vanahub' and profile.id == document.activeProfileId,
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

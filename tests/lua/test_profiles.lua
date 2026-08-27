package.path = 'addon/vanahub/versions/0.1.0/?.lua;' .. package.path;

local profiles = require 'profiles';

local function equal(actual, expected, message)
    if actual ~= expected then
        error((message or 'values differ') .. ': expected ' .. tostring(expected) .. ', got ' .. tostring(actual), 2);
    end
end

local installed = {
    zebra = { name = 'Zebra' },
    alpha = { name = 'Alpha' },
};

local legacy = profiles.normalize(installed, installed);
equal(legacy.schemaVersion, 2, 'legacy schema migrated');
equal(legacy.activeProfileId, 'default', 'default profile selected');
equal(legacy.profiles[1].addons[1].id, 'alpha', 'legacy addons sorted by name');
equal(legacy.profiles[1].addons[1].autoLoad, false, 'legacy addons default off');
equal(legacy.profiles[1].addons[2].id, 'zebra', 'legacy order deterministic');

local restored = profiles.normalize({
    schemaVersion = 2,
    activeProfileId = 'raid',
    profiles = {
        { id = 'default', name = 'Default', addons = {
            { id = 'zebra', autoLoad = true },
            { id = 'missing', autoLoad = true },
            { id = 'zebra', autoLoad = false },
        } },
        { id = 'raid', name = 'Raid', addons = { { id = 'alpha', autoLoad = true } } },
    },
}, installed);
equal(restored.activeProfileId, 'raid', 'active profile restored');
equal(restored.profiles[1].addons[1].id, 'zebra', 'saved order retained');
equal(restored.profiles[1].addons[1].autoLoad, true, 'saved auto-load retained');
equal(#restored.profiles[1].addons, 2, 'missing and duplicate entries normalized');
equal(restored.profiles[1].addons[2].id, 'alpha', 'new installed addon appended');

local created = profiles.add(restored, 'Solo', false);
equal(created.name, 'Solo', 'profile created');
equal(created.addons[1].id, 'alpha', 'new profile copies active order');
equal(created.addons[1].autoLoad, false, 'new profile starts disabled');
local duplicate = profiles.add(restored, 'Solo', true);
equal(duplicate.name, 'Solo 2', 'duplicate name made unique');
equal(duplicate.addons[1].autoLoad, false, 'disabled value duplicated');

local renamed, rename_error = profiles.rename(restored, duplicate.id, 'Raid');
equal(renamed, false, 'duplicate rename rejected');
equal(rename_error, 'Profile names must be unique.', 'duplicate rename explains failure');
equal(profiles.rename(restored, duplicate.id, 'Party'), true, 'profile renamed');

restored.installed.bravo = { name = 'Bravo' };
profiles.add_installed(restored, 'bravo');
for _, profile in ipairs(restored.profiles) do
    local entry = profile.addons[#profile.addons];
    equal(entry.id, 'bravo', 'new install appended to every profile');
    equal(entry.autoLoad, profile.id == restored.activeProfileId, 'new install enabled only in active profile');
end

local active = profiles.active(restored);
local last = #active.addons;
equal(profiles.move(active, last, -1), true, 'addon moves up');
equal(active.addons[last - 1].id, 'bravo', 'move changes order');
equal(profiles.move(active, 1, -1), false, 'invalid move rejected');

profiles.remove_installed(restored, 'bravo');
for _, profile in ipairs(restored.profiles) do
    for _, entry in ipairs(profile.addons) do
        if entry.id == 'bravo' then error('uninstall left a profile reference'); end
    end
end

local remove_id = restored.activeProfileId;
equal(profiles.remove(restored, remove_id), true, 'active profile removed');
if restored.activeProfileId == remove_id then error('removing active profile did not choose a replacement'); end

local singleton = profiles.normalize(nil, { });
equal(profiles.remove(singleton, 'default'), false, 'last profile cannot be deleted');

print('profile tests passed');

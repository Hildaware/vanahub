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
equal(legacy.schemaVersion, 3, 'legacy schema migrated');
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

local portable = profiles.normalize({
    schemaVersion = 3,
    profiles = { { id = 'portable', name = 'Portable', addons = {
        { id = 'missing-addon', autoLoad = true }, { id = 'alpha', autoLoad = true },
    } } }, activeProfileId = 'portable',
}, { alpha = installed.alpha, zebra = installed.zebra });
equal(#portable.profiles[1].addons, 3, 'v3 retains unresolved addons and appends installed addons');
equal(portable.profiles[1].addons[1].id, 'missing-addon', 'unresolved addon order retained');
equal(portable.profiles[1].addons[1].autoLoad, false, 'unresolved addon disabled');

local imported, import_error = profiles.import_profile(portable, {
    schemaVersion = 1,
    profile = { name = 'Portable', addons = {
        { id = 'alpha', autoLoad = true, settings = true, source = { builtin = true } },
        { id = 'another-missing', autoLoad = true, settings = false, source = { builtin = true } },
    } },
});
equal(import_error, nil, 'valid portable profile imported');
equal(imported.name, 'Portable 2', 'imported profile name made unique');
equal(imported.addons[1].autoLoad, true, 'installed imported addon retains auto-load');
equal(imported.addons[2].id, 'another-missing', 'unresolved imported addon retained');
equal(imported.addons[2].autoLoad, false, 'unresolved imported addon disabled');
equal(profiles.import_profile(portable, { schemaVersion = 2 }), nil, 'invalid portable manifest rejected');
equal(profiles.import_profile(portable, { schemaVersion = 1,
    profile = { name = 'Bad', addons = { { id = '../bad', autoLoad = true,
        settings = false, source = { builtin = true } } } } }), nil, 'unsafe imported addon id rejected');

local catalog_manifest = {
    schemaVersion = 1, id = 'starter-profile', name = 'Starter Profile',
    description = 'A useful starting point.', author = 'VanaHub', version = '1.0.0',
    downloadUrl = 'https://github.com/Hildaware/vanahub-catalog/releases/download/profile-starter-profile-v1.0.0/starter-profile-1.0.0.vanahub-profile.zip',
    sha256 = string.rep('a', 64), compressedSize = 100,
    addons = {
        { id = 'alpha', autoLoad = true, settings = true, source = { builtin = true } },
        { id = 'zebra', autoLoad = false, settings = false, source = { builtin = true }, version = '1.2.3' },
    },
};
equal(profiles.validate_catalog(catalog_manifest), true, 'valid catalog profile accepted');
equal(catalog_manifest.addons[1].settings, true, 'catalog profile advertises archived settings');

local custom_manifest = {
    schemaVersion = 1, id = 'custom-profile', name = 'Custom Profile',
    description = 'From a configured custom repository.', author = 'Tester', version = '1.0.0',
    downloadUrl = 'https://github.com/Hildaware/vanahub-catalog/releases/download/profile-custom-profile-v1.0.0/custom-profile-1.0.0.vanahub-profile.zip',
    sha256 = string.rep('b', 64), compressedSize = 100,
    addons = { { id = 'alpha', autoLoad = true, settings = true,
        source = { builtin = false, name = 'Custom', url = 'https://example.com/index.json' } } },
};
equal(profiles.validate_catalog(custom_manifest), true, 'custom catalog profile accepted');
equal(custom_manifest.addons[1].source.url, 'https://example.com/index.json',
    'custom catalog source retained');
equal(profiles.validate_catalog({ schemaVersion = 1, id = 'bad', name = 'Bad',
    description = 'Bad duplicate.', author = 'Tester', version = '1.0.0',
    downloadUrl = 'https://github.com/Hildaware/vanahub-catalog/releases/download/profile-bad-v1.0.0/bad-1.0.0.vanahub-profile.zip',
    sha256 = string.rep('c', 64), compressedSize = 100, addons = {
        { id = 'alpha', autoLoad = true, settings = false, source = { builtin = true } },
        { id = 'alpha', autoLoad = false, settings = false, source = { builtin = true } },
    } }), false, 'duplicate catalog addons rejected');

print('profile tests passed');

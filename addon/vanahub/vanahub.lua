addon.name = 'vanahub';
addon.author = 'VanaHub contributors';
addon.version = '0.1.0';
addon.desc = 'VanaHub browses and installs screened Ashita v4 addons.';
addon.link = 'https://github.com/';

require 'common';

local function read_text(path)
    local file = io.open(path, 'rb');
    if (file == nil) then return nil; end
    local value = file:read('*all');
    file:close();
    return value and value:gsub('%s+$', '') or nil;
end

-- The stable bootstrap activates a fully staged version before loading its DLL.
local active_path = addon.path .. 'active.txt';
local pending_path = addon.path .. 'pending.txt';
local pending = read_text(pending_path);
if (pending ~= nil and pending:match('^[0-9A-Za-z._-]+$') ~= nil) then
    local probe = addon.path .. 'versions\\' .. pending .. '\\main.lua';
    local file = io.open(probe, 'rb');
    if (file ~= nil) then
        file:close();
        local output = io.open(active_path .. '.tmp', 'wb');
        if (output ~= nil) then
            output:write(pending .. '\n');
            output:close();
            if ashita.fs.exists(active_path) then ashita.fs.remove(active_path); end
            if ashita.fs.rename(active_path .. '.tmp', active_path) then ashita.fs.remove(pending_path); end
        end
    end
end

local active = read_text(active_path) or addon.version;
assert(active:match('^[0-9A-Za-z._-]+$') ~= nil, 'Invalid active VanaHub version.');
addon.active_version = active;
local version_root = addon.path .. 'versions\\' .. active .. '\\';
package.path = version_root .. '?.lua;' .. version_root .. '?\\init.lua;' .. package.path;
dofile(version_root .. 'main.lua');

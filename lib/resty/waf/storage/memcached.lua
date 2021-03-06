local _M = {}

_M.version = "0.8"

local cjson       = require "cjson"
local logger      = require "resty.waf.log"
local memcached_m = require "resty.memcached"

function _M.initialize(waf, storage, col)
	local memcached = memcached_m:new()
	local host      = waf._storage_memcached_host
	local port      = waf._storage_memcached_port

	local ok, err = memcached:connect(host, port)
	if (not ok) then
		logger.log(waf, "Error in connecting to memcached: " .. err)
		storage[col] = {}
		return
	end

	local serialized, flags, err = memcached:get(col)
	if (err) then
		logger.log(waf, "Error retrieving " .. col .. ": " .. err)
		storage[col] = {}
		return
	end

	local ok, err = memcached:set_keepalive(10000, 100)
	if (not ok) then
		logger.log(waf, "Error setting memcached keepalive: " .. err)
	end

	local altered = false

	if (not serialized) then
		logger.log(waf, "Initializing an empty collection for " .. col)
		storage[col] = {}
	else
		local data = cjson.decode(serialized)

		-- because we're serializing out the contents of the collection
		-- we need to roll our own expire handling
		for key in pairs(data) do
			if (not key:find("__", 1, true) and data["__expire_" .. key]) then
				logger.log(waf, "checking " .. key)
				if (data["__expire_" .. key] < ngx.time()) then
					logger.log(waf, "Removing expired key: " .. key)
					data["__expire_" .. key] = nil
					data[key] = nil
					altered = true
				end
			end
		end

		storage[col] = data
	end

	storage[col]["__altered"] = altered
end

function _M.persist(waf, col, data)
	local serialized = cjson.encode(data)
	logger.log(waf, 'Persisting value: ' .. tostring(serialized))

	local memcached = memcached_m:new()
	local host      = waf._storage_memcached_host
	local port      = waf._storage_memcached_port

	local ok, err = memcached:connect(host, port)
	if (not ok) then
		logger.log(waf, "Error in connecting to memcached: " .. err)
		return
	end

	local ok, err = memcached:set(col, serialized)
	if (not ok) then
		logger.log(waf, "Error persisting storage data: " .. err)
	end

	local ok, err = memcached:set_keepalive(10000, 100)
	if (not ok) then
		logger.log(waf, "Error setting memcached keepalive: " .. err)
	end
end


return _M

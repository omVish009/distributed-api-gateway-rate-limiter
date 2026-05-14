local tokens_key = KEYS[1]
local timestamp_key = KEYS[2]

local capacity = tonumber(ARGV[1])
local refill_rate_per_minute = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local refill_rate_per_second = refill_rate_per_minute / 60.0

local last_tokens = tonumber(redis.call("GET", tokens_key))
if last_tokens == nil then
    last_tokens = capacity
end

local last_refreshed = tonumber(redis.call("GET", timestamp_key))
if last_refreshed == nil then
    last_refreshed = now
end

local delta = math.max(0, now - last_refreshed)
local replenished = delta * refill_rate_per_second
local filled_tokens = math.min(capacity, last_tokens + replenished)

local allowed = 0
local new_tokens = filled_tokens
local retry_after = 0

if filled_tokens >= 1 then
    allowed = 1
    new_tokens = filled_tokens - 1
else
    local missing = 1 - filled_tokens
    if refill_rate_per_second > 0 then
        retry_after = math.ceil(missing / refill_rate_per_second)
    else
        retry_after = 60
    end
end

redis.call("SETEX", tokens_key, 120, tostring(new_tokens))
redis.call("SETEX", timestamp_key, 120, tostring(now))

return { allowed, math.floor(new_tokens), retry_after }
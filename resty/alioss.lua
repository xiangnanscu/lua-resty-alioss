local cjson_encode = require "cjson".encode
local Array = require "resty.array"
local dotenv = require "resty.dotenv"
local encode_base64 = ngx.encode_base64
local hmac_sha1 = ngx.hmac_sha1
local ngx_time = ngx.time


local JSON_ENV
local function getenv(key)
  if not JSON_ENV then
    local json = dotenv { path = { '.env', '.env.local' } }
    JSON_ENV = json
  end
  if key then
    return JSON_ENV[key]
  else
    return JSON_ENV
  end
end

local size_table = {
  k = 1024,
  m = 1024 * 1024,
  g = 1024 * 1024 * 1024,
  kb = 1024,
  mb = 1024 * 1024,
  gb = 1024 * 1024 * 1024
}
local function byte_size_parser(t)
  if type(t) == "string" then
    local unit = t:gsub("^(%d+)([^%d]+)$", "%2"):lower()
    local ts = t:gsub("^(%d+)([^%d]+)$", "%1"):lower()
    local bytes = size_table[unit]
    assert(bytes, "invalid size unit: " .. unit)
    local num = tonumber(ts)
    assert(num, "can't convert `" .. ts .. "` to a number")
    return num * bytes
  elseif type(t) == "number" then
    return t
  else
    error("invalid type:" .. type(t))
  end
end

local ALIOSS_KEY = getenv("ALIOSS_KEY") or ""
local ALIOSS_SECRET = getenv("ALIOSS_SECRET") or ""
local ALIOSS_BUCKET = getenv("ALIOSS_BUCKET")
-- Bytes
local ALIOSS_SIZE = byte_size_parser(getenv("ALIOSS_SIZE") or "10MB")
local ALIOSS_LIFETIME = tonumber(getenv("ALIOSS_LIFETIME")) or 30 -- server side lifetime
local ALIOSS_EXPIRATION_DAYS = tonumber(getenv("ALIOSS_EXPIRATION_DAYS") or 180)
-- https://help.aliyun.com/document_detail/31988.html?spm=5176.doc32074.6.868.KQbmQM#title-5go-s2f-dnw
local function get_policy_time(seconds)
  local s = os.date("%Y-%m-%d %H:%M:%S", ngx_time() + seconds):gsub(' ', 'T') .. ".000Z"
  return s
end

-- https://help.aliyun.com/document_detail/31988.html?spm=5176.doc32074.6.868.KQbmQM#section-d5z-1ww-wdb
---@param options {size?:string,lifetime?:number, bucket?:string,key?:string}
---@return {conditions:table, expiration:string}
local function get_policy(options)
  local conditions = Array {}
  local policy = {
    conditions = conditions,
    expiration = get_policy_time(tonumber(options.lifetime or ALIOSS_LIFETIME)),
  }
  conditions:push { bucket = options.bucket or ALIOSS_BUCKET }
  local size = options.size
  if type(size) == "table" then
    conditions:push { "content-length-range", size[1], size[2] }
  elseif type(size) == 'string' or type(size) == 'number' then
    conditions:push { "content-length-range", 1, byte_size_parser(size) }
  else
    conditions:push { "content-length-range", 1, ALIOSS_SIZE }
  end
  if options.key then
    conditions:push { "eq", "$key", options.key }
  end
  return policy
end

---@param options {size?:string, key?:string,bucket?:string,lifetime?:number, key_secret?: string,key_id?:string,success_action_status?:number}
---@return {policy:string, OSSAccessKeyId:string, signature:string, success_action_status?:number}
local function get_payload(options)
  -- https://github.com/ali-sdk/ali-oss/blob/master/lib/client.js#L134
  -- https://github.com/bungle/lua-resty-nettle/blame/master/README.md#L136
  local data = {}
  data.policy = encode_base64(cjson_encode(get_policy(options)))
  data.signature = encode_base64(hmac_sha1(options.key_secret or ALIOSS_SECRET, data.policy))
  data.OSSAccessKeyId = options.key_id or ALIOSS_KEY
  if options.success_action_status then
    data.success_action_status = options.success_action_status
  end
  return data
end

return {
  get_policy = get_policy,
  get_payload = get_payload
}

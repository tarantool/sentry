#!/usr/bin/env tarantool

local checks = require('checks')
local errors = require('errors')
local json = require('json')
local log = require('log')
local fiber = require('fiber')
local digest = require('digest')

local http_client = require('http.client').new({max_connections = 10})

local sentry_error = errors.new_class('sentry_error')

if rawget(_G, "_sentry") == nil then
    _G._sentry = {
        started = false,
        fiber = nil,
        channel = fiber.channel(1024)
    }
end


local function iso8601()
    local t = os.date("!*t")
    return string.format("%04d-%02d-%02dT%02d:%02d:%02d",
        t["year"], t["month"], t["day"], t["hour"], t["min"], t["sec"])
end


local function parse_traceback(traceback)
    checks('?string')

    if traceback == nil then
        return nil
    end

    local lines = string.split(traceback, '\n')

    local res = {}

    for _, line in ipairs(lines) do
        local place, fun = string.match(line, "^%s*(.*) in (.*)$")

        if place ~= nil then
            local file, line = string.match(place, "(.*):(.*):")

            if file == nil then
                file = string.match(place, "(.*):")
            end

            if line ~= nil then
                line = tonumber(line)
            end

            local fun_name = string.match(fun, "function '(.*)'")

            if fun_name == nil then
                fun_name = string.match(fun, "function (.*)")

                if fun_name == nil then
                    fun_name = fun
                end
            end

            table.insert(
                res, 1,
                {
                    filename = file,
                    ["function"] = fun_name,
                    lineno = line,
                }
            )
        end
    end

    return res
end

local function parse_host_port(protocol, host)
    local i = string.find(host, ":")
    if not i then
        return host, protocol == 'https' and 443 or 80
    end

    local port_str = string.sub(host, i + 1)
    local port = tonumber(port_str)
    if not port then
        return nil, nil, "illegal port: " .. port_str
    end

    return string.sub(host, 1, i - 1), port
end


local function parse_dsn(dsn)
    local obj = {}

    -- '{PROTOCOL}://{PUBLIC_KEY}:{SECRET_KEY}@{HOST}/{PATH}{PROJECT_ID}'
    obj.protocol, obj.public_key, obj.long_host,
    obj.path, obj.project_id =
        string.match(dsn, "^([^:]+)://([^:]+)@([^/]+)(.*/)(.+)$")

    if obj.protocol and obj.public_key and obj.long_host
        and obj.project_id then

        local host, port, err = parse_host_port(obj.protocol, obj.long_host)

        if not host then
            return nil, err
        end

        obj.request_uri = string.format("%sapi/%s/store/", obj.path, obj.project_id)
        obj.server = string.format("%s://%s:%d%s", obj.protocol, host, port,
            obj.request_uri)

        return obj
    end

    return nil, sentry_error:new("failed to parse DSN string")
end

local function generate_auth_header(public_key)
    checks('string')
    return string.format(
        "Sentry sentry_version=7, sentry_client=%s, sentry_key=%s",
        "tarantool/0.1",
        public_key)
end

local function is_error_object(err)
    return (type(err) == 'table'
        and err.err ~= nil
        and err.str ~= nil
        and err.line ~= nil
        and err.file ~= nil
        and err.class_name ~= nil
    )
end

local function send_report(dsn, tbl, conf)
    checks('string', 'table', '?table')
    local event_id = string.hex(digest.urandom(16))

    tbl.event_id  = event_id
    tbl.timestamp = iso8601()
    tbl.platform  = "tarantool"

    if conf ~= nil then
        tbl.tags = conf.tags
        tbl.extra = conf.extra

        if conf.level then
            tbl.level = conf.level
        end
    end

    tbl.server_name = 'undefined'

    local parsed, err = parse_dsn(dsn)

    if parsed == nil then
        return nil, err
    end

    local json_str = json.encode(tbl)
    local auth_header = generate_auth_header(parsed.public_key)


    local headers = {
            ['Content-Type'] = 'applicaion/json',
            ['User-Agent'] = "tarantool",
            ['X-Sentry-Auth'] = auth_header
    }

    local result = http_client:post(
        parsed.server,
        json_str,
        {headers=headers})

    if result.status ~= 200 then
        return nil, sentry_error:new("Failed to send to sentry: %s", result.body)
    end

    return tbl.event_id
end

local function send_loop()
    while true do
        local dsn, payload, conf = unpack(_G._sentry.channel:get())

        local res, err = sentry_error:pcall(send_report, dsn, payload, conf)

        if res == nil then
            log.error(err)
        end
    end
end

local function start()
    if not _G._sentry.started then
        _G._sentry.started = true
        _G._sentry.fiber = fiber.create(send_loop)
    end
end


local function capture_message(dsn, conf, msg, ...)
    checks('?string', 'table', 'string')

    if dsn == nil then
        return true
    end

    start()

    local payload = {
        message = {
            message=msg,
            params = {...},
        }
    }

    _G._sentry.channel:put({dsn, payload, conf})

    return true
end

local function capture_exception(dsn, err, conf)
    checks('?string', 'table|cdata', '?table')

    if dsn == nil then
        return true
    end

    start()

    local payload
    if is_error_object(err) then
        payload = {
            culprit = string.format("%s:%s", err.file, err.line),
            exception = { {
                    type = err.class_name,
                    value = err.err,
                    stacktrace = {frames=parse_traceback(err.stack)},
            } },
        }
    else
        payload = {
            message = tostring(err)
        }
    end

    _G._sentry.channel:put({dsn, payload, conf})

    return true
end

local function sentry_pcall(dsn, ...)
    checks('?string')
    local res, err = sentry_error:pcall(...)

    if err ~= nil then
        capture_exception(dsn, err)
    end

    return res, err
end

return {
    capture_message = capture_message,
    capture_exception = capture_exception,
    pcall = sentry_pcall
}

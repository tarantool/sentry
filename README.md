# Send exceptions from Tarantool to Sentry

This module allows you to easily send exceptions from your Tarantool
applications to the [Sentry](https://sentry.io) service. Sentry then
allows you to drill down into the root cause, and even send
notifications to [PagerDuty](https://www.pagerduty.com). Both Sentry
and PagerDuty are an inexpensive way to monitor errors in your cloud
installations of Tarantool.

## Usage

```lua
local sentry = require('sentry')

-- "DSN" is your API key and can be generated at http://sentry.io
local dsn = 'https://<token>@sentry.io/<project-id>'


local function my_function(param)
    error("Something bad happened")
end

-- This will return function's return value in 'res' on success,
-- and on error it will report that error to Sentry, and return
-- it in 'err'
local res, err = sentry.pcall(dsn, my_function, 123)
```

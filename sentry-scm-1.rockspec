package = 'sentry'
version = 'scm-1'
source  = {
    url = '/dev/null',
}

dependencies = {
    'tarantool',
    'lua >= 5.1',
    'errors',
    'checks'
}

build = {
    type = "builtin",
    modules = {
        ["sentry"] = "sentry.lua",
    }
}

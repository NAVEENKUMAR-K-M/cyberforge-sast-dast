"""PHP sources, sinks and sanitisers, kept as data apart from the interpreter."""
import re

# superglobal -> parameter location
SUPERGLOBALS = {
    "$_GET": "query",
    "$_POST": "body",
    "$_REQUEST": "any",
    "$_COOKIE": "cookie",
    "$_FILES": "file",
    "$_SERVER": "header",
    "$_SESSION": "session",
    "$_ENV": None,
    "$GLOBALS": None,
}
TAINTED_SERVER_KEYS = {"PHP_SELF": "path", "REQUEST_URI": "path", "QUERY_STRING": "path", "PATH_INFO": "path"}

# function -> (cwe, argument index, or None for every argument)
SINK_FUNCS = {
    "mysqli_query": (89, 1), "mysql_query": (89, 0), "mysqli_multi_query": (89, 1),
    "mysqli_real_query": (89, 1), "mysqli_prepare": (89, 1), "pg_query": (89, None),
    "pg_prepare": (89, None), "pg_send_query": (89, None), "sqlite_query": (89, None),
    "mssql_query": (89, 0), "odbc_exec": (89, 1), "db2_exec": (89, 1), "sqlsrv_query": (89, 1),
    "system": (78, 0), "exec": (78, 0), "shell_exec": (78, 0), "passthru": (78, 0),
    "popen": (78, 0), "proc_open": (78, 0), "pcntl_exec": (78, 0),
    "file_get_contents": (22, 0), "fopen": (22, 0), "readfile": (22, 0), "file": (22, 0),
    "unlink": (22, 0), "file_put_contents": (22, 0), "copy": (22, None), "rename": (22, None),
    "opendir": (22, 0), "scandir": (22, 0), "highlight_file": (22, 0), "show_source": (22, 0),
    "parse_ini_file": (22, 0), "rmdir": (22, 0), "move_uploaded_file": (22, 1), "simplexml_load_file": (22, 0),
    "unserialize": (502, 0),
    "eval": (94, 0), "assert": (94, 0), "create_function": (94, None),
    "printf": (79, None), "vprintf": (79, None), "print_r": (79, 0), "var_dump": (79, None),
    "wp_redirect": (601, 0), "http_redirect": (601, 0), "redirect": (601, 0),
}
SINK_METHODS = {
    "query": (89, 0), "exec": (89, 0), "prepare": (89, 0), "multi_query": (89, 0),
    "real_query": (89, 0), "querysingle": (89, 0), "rawquery": (89, 0),
    "raw": (89, 0), "whereraw": (89, 0), "selectraw": (89, 0), "orderbyraw": (89, 0),
    "havingraw": (89, 0), "statement": (89, 0), "unprepared": (89, 0),
    "download": (22, 0), "file": (22, 0),  # Laravel: response()->download($path), response()->file($path)
}
# Binding is the safe way to pass values, so a tainted value here is marked safe.
BIND_FUNCS = {"mysqli_stmt_bind_param": 2, "pg_query_params": 2}
BIND_METHODS = {"bindparam": 1, "bindvalue": 1, "bind_param": 1, "execute": 0}

KILL_FUNCS = {
    "md5", "sha1", "hash", "crc32", "password_hash", "password_verify", "hash_hmac", "base64_encode",
    "bin2hex", "dechex", "urlencode", "rawurlencode", "http_build_query", "strlen", "count", "sizeof", "time",
    "date", "uniqid", "rand", "mt_rand", "random_int", "random_bytes", "is_numeric", "is_int", "is_string",
    "is_array", "is_null", "isset", "empty", "array_key_exists", "in_array", "preg_match", "strpos", "stripos",
    "strcmp", "strcasecmp", "ctype_digit", "ctype_alnum", "ctype_alpha", "file_exists", "is_file", "is_dir",
    "function_exists", "defined", "session_start", "session_id", "headers_sent", "mb_strlen", "ord",
    "array_keys_exists", "filesize", "number_format", "round", "floor", "ceil", "max", "min", "array_sum",
}
NUMERIC_FUNCS = {"intval", "floatval", "doubleval", "abs", "boolval"}
# function -> sanitiser label
SANITIZERS = {
    "htmlspecialchars": "html_escape", "htmlentities": "html_escape", "esc_html": "html_escape",
    "esc_attr": "html_escape", "e": "html_escape", "h": "html_escape",
    "mysqli_real_escape_string": "sql_escape", "mysql_real_escape_string": "sql_escape",
    "mysql_escape_string": "sql_escape", "pg_escape_string": "sql_escape",
    "sqlite_escape_string": "sql_escape", "pg_escape_literal": "sql_quote",
    "addslashes": "addslashes",
    "escapeshellarg": "shell_arg", "escapeshellcmd": "shell_cmd",
    "basename": "path_base", "realpath": "path_real",
}
SANITIZER_METHODS = {
    "real_escape_string": "sql_escape", "escape_string": "sql_escape", "escapestring": "sql_escape",
    "quote": "sql_quote",
}
PASSTHROUGH_FUNCS = {
    "trim", "ltrim", "rtrim", "chop", "strtolower", "strtoupper", "ucfirst", "ucwords", "lcfirst", "substr",
    "str_replace", "str_ireplace", "preg_replace", "substr_replace", "strrev", "stripslashes", "stripcslashes",
    "urldecode", "rawurldecode", "base64_decode", "html_entity_decode", "htmlspecialchars_decode", "json_decode",
    "json_encode", "implode", "join", "explode", "str_split", "preg_split", "array_values", "array_merge",
    "array_map", "array_filter", "array_slice", "array_pop", "array_shift", "array_reverse", "array_unique",
    "nl2br", "strip_tags", "strtr", "wordwrap", "mb_substr", "mb_strtolower", "mb_strtoupper", "pack", "unpack",
    "serialize", "strstr", "stristr", "strrchr", "current", "end", "reset", "next", "sprintf", "vsprintf",
    "parse_url", "pathinfo", "dirname", "str_pad", "str_repeat", "ctype_print", "addcslashes", "quotemeta",
    "iconv", "utf8_encode", "utf8_decode", "mb_convert_encoding", "array_keys", "array_flip", "array_combine",
    "filter_var", "filter_input", "htmlspecialchars_decode", "strval", "print", "settype", "compact",
    "array_column", "array_diff", "array_intersect", "array_key_first", "array_key_last", "array_fill",
    "array_pad", "array_push", "array_unshift", "array_search", "extract", "lcfirst", "nl_langinfo", "ob_get_clean",
}
FETCH_FUNCS = {
    "mysqli_fetch_assoc", "mysqli_fetch_array", "mysqli_fetch_row", "mysqli_fetch_object", "mysqli_fetch_all",
    "mysql_fetch_assoc", "mysql_fetch_array", "mysql_fetch_row", "mysql_fetch_object", "mysql_result",
    "pg_fetch_assoc", "pg_fetch_array", "pg_fetch_row", "pg_fetch_all", "pg_fetch_result", "mysqli_stmt_get_result",
    "sqlite_fetch_array",
}
FETCH_METHODS = {
    "fetch", "fetchall", "fetch_assoc", "fetch_array", "fetch_row", "fetch_object", "fetch_all", "fetcharray",
    "fetchcolumn", "fetchobject", "get_result", "first", "get", "getresult",
}
HEADER_SAFE_TYPES = ("application/json", "text/plain", "text/csv", "application/xml", "text/xml", "application/pdf",
                     "image/", "application/octet-stream")

# sanitiser label -> the reason shown when it protects a finding
LABEL_TEXT = {
    "int": "numeric cast or validation",
    "allowlist": "value checked against an allowlist",
    "html_escape": "HTML escaping that fits the output context",
    "sql_escape": "SQL escaping inside a quoted value",
    "sql_quote": "SQL quoting function",
    "shell_arg": "escapeshellarg",
    "path_base": "basename strips directories",
    "path_real": "realpath with a prefix check",
    "bound": "bound query parameter",
    "fixed_url": "fixed URL prefix before the input",
    "non_html": "response isn't HTML",
}
UNSAFE_REGEX_CHARS = set("'\"<>/\\;&|`$(){}%#")

# Recognising a request object by its role. Names only ever raise a guess, so they rank lower.
REQUEST_VAR_NAMES = {"$request", "$req", "$httprequest", "$http_request"}
REQUEST_PROPS = {"request", "input", "req"}
REQUEST_TYPE_SUFFIXES = ("request", "serverrequestinterface", "requestinterface")
# Methods that hand back a request object from somewhere else.
REQUEST_GETTERS = {"getrequest", "request", "createfromglobals", "fromglobals"}
# Parts of a request object -> where their values come from.
REQUEST_BAGS = {"query": "query", "request": "body", "cookies": "cookie", "headers": "header",
                "attributes": "path", "files": "file", "get": "query", "post": "body", "cookie": "cookie"}
# Properties of a request object that aren't values a visitor chose.
REQUEST_NON_INPUT_PROPS = {"method", "session", "user", "server", "route", "ip", "url", "uri", "path", "host", "scheme",
                           "port", "locale", "format"}
# Methods on a request object -> where the value comes from. These are verbs shared across frameworks.
REQUEST_METHODS = {
    "input": "any", "get": "any", "all": "any", "only": "any", "except": "any", "param": "any", "params": "any",
    "getparam": "any", "getparams": "any", "getvar": "any", "getgetpost": "any", "getpostget": "any", "get_post": "any",
    "validated": "any", "validate": "any", "string": "any", "str": "any",
    "query": "query", "getquery": "query", "getget": "query", "getqueryparam": "query", "getqueryparams": "query",
    "post": "body", "getpost": "body", "json": "json", "getjson": "json", "getjsonvar": "json", "getparsedbody": "body",
    "getparsedbodyparam": "body", "getbody": "body", "getcontent": "body", "getrawinput": "body", "getinput": "body",
    "cookie": "cookie", "getcookie": "cookie", "getcookieparams": "cookie",
    "header": "header", "getheader": "header", "getheaderline": "header",
    "route": "path", "segment": "path", "getattribute": "path",
    "file": "file", "getfile": "file",
}
# SQL recognised by what the string says, whichever library runs it.
SQL_STATEMENT = re.compile(
    r"^\s*\(?\s*(select\b.+?\bfrom\b|insert\s+(ignore\s+)?into\b|replace\s+into\b|update\b.+?\bset\b|delete\s+from\b)",
    re.I | re.S)
# A string reading like SQL is only being logged here, not run.
LOGGING_CALLS = {"debug", "info", "notice", "warning", "warn", "error", "critical", "alert", "emergency", "log", "trace",
                 "error_log", "syslog", "trigger_error", "logmessage", "writelog"}
# Built-ins that call a function they're given: name -> (position of the callback, how it's called).
HIGHER_ORDER = {
    "array_map": (0, "each"), "array_filter": (1, "keep"), "array_walk": (1, "each"), "array_walk_recursive": (1, "each"),
    "usort": (1, "each"), "uasort": (1, "each"), "uksort": (1, "each"), "array_reduce": (1, "each"),
    "preg_replace_callback": (1, "subject"), "call_user_func": (0, "direct"), "call_user_func_array": (0, "spread"),
}
# Words that mean "show this template", when the template is named without a file extension.
RENDER_VERBS = {"view", "render", "display", "fetch", "make", "load", "template", "partial", "renderview", "renderpartial",
                "renderfile", "show", "blade", "twig", "smarty", "assign_view"}
# Words that hand a template its variables: ->with('name', $value) or ->assign('name', $value).
ASSIGN_VERBS = {"with", "assign", "addattribute", "setvar", "assignbyref"}

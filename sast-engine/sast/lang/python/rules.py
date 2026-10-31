"""What counts as input, what counts as dangerous, and what protects. Data only, no logic."""
from __future__ import annotations

import re

# The framework's request object, by where each part of it comes from.
REQUEST_QUALIFIED = {"flask.request", "quart.request", "flask.globals.request"}
REQUEST_ATTRS = {
    "args": "query", "query_params": "query", "form": "body", "values": "any", "json": "json", "cookies": "cookie",
    "headers": "header", "files": "file", "view_args": "path", "path_params": "path", "data": "body", "body": "body",
    "GET": "query", "POST": "body", "COOKIES": "cookie", "META": "header", "FILES": "file",
}
# Calls on the request object that return a part of it: request.get_json(), await request.form().
REQUEST_CALLS = {"get_json": "json", "json": "json", "form": "body", "body": "body", "get_data": "body", "values": "any"}
REQUEST_RAW = {"data", "body"}
REQUEST_RAW_CALLS = {"get_data", "body"}
REQUEST_PATH_ATTRS ={"path", "full_path", "query_string", "url"}
BAG_GET = {"get", "getlist", "get_all", "pop"}
BAG_ALL = {"to_dict", "items", "values", "keys", "copy", "dict", "lists", "multi_items", "getall"}

# qualified function -> (cwe, argument index, keyword name)
SINK_FUNCS = {
    "os.system": (78, 0, "command"), "os.popen": (78, 0, "cmd"), "subprocess.getoutput": (78, 0, "cmd"),
    "subprocess.getstatusoutput": (78, 0, "cmd"), "asyncio.create_subprocess_shell": (78, 0, "cmd"),
    "commands.getoutput": (78, 0, "cmd"),
    "eval": (94, 0, "source"), "exec": (94, 0, "source"), "compile": (94, 0, "source"),
    "importlib.import_module": (94, 0, "name"), "__import__": (94, 0, "name"),
    "pickle.loads": (502, 0, "data"), "pickle.load": (502, 0, "file"), "cPickle.loads": (502, 0, "data"),
    "marshal.loads": (502, 0, "data"), "dill.loads": (502, 0, "data"), "jsonpickle.decode": (502, 0, "string"),
    "shelve.open": (502, 0, "filename"),
    "sqlalchemy.text": (89, 0, "text"), "sqlalchemy.sql.text": (89, 0, "text"), "pandas.read_sql": (89, 0, "sql"),
    "pandas.read_sql_query": (89, 0, "sql"),
    "open": (22, 0, "file"), "io.open": (22, 0, "file"), "os.open": (22, 0, "path"), "os.remove": (22, 0, "path"),
    "os.unlink": (22, 0, "path"), "os.rmdir": (22, 0, "path"), "os.removedirs": (22, 0, "path"),
    "os.rename": (22, 0, "src"), "os.replace": (22, 0, "src"), "os.listdir": (22, 0, "path"),
    "os.scandir": (22, 0, "path"), "os.mkdir": (22, 0, "path"), "os.makedirs": (22, 0, "name"),
    "os.walk": (22, 0, "top"), "shutil.copy": (22, 0, "src"), "shutil.copyfile": (22, 0, "src"),
    "shutil.copy2": (22, 0, "src"), "shutil.move": (22, 0, "src"), "shutil.rmtree": (22, 0, "path"),
    "shutil.copytree": (22, 0, "src"),
    "flask.send_file": (22, 0, "path_or_file"), "fastapi.responses.FileResponse": (22, 0, "path"),
    "starlette.responses.FileResponse": (22, 0, "path"),
    "flask.render_template_string": (79, 0, "source"), "django.template.Template": (79, 0, "template_string"),
    "django.db.models.expressions.RawSQL": (89, 0, "sql"), "django.db.models.RawSQL": (89, 0, "sql"),
    "flask.redirect": (601, 0, "location"), "werkzeug.utils.redirect": (601, 0, "location"),
    "django.shortcuts.redirect": (601, 0, "to"), "django.http.HttpResponseRedirect": (601, 0, "redirect_to"),
    "django.http.HttpResponsePermanentRedirect": (601, 0, "redirect_to"),
    "fastapi.responses.RedirectResponse": (601, 0, "url"), "starlette.responses.RedirectResponse": (601, 0, "url"),
}
# Used when the import can't be followed (`from flask import *`): a distinctive name alone is enough.
SINK_BY_TAIL = {name.rsplit(".", 1)[-1]: info for name, info in SINK_FUNCS.items()
                if name.rsplit(".", 1)[-1] in {"redirect", "RedirectResponse", "FileResponse", "send_file",
                                                "render_template_string", "HttpResponseRedirect"}}
# Methods, on any object, whose first argument is the dangerous one.
SINK_METHODS = {
    "execute": (89, 0, "sql"), "executemany": (89, 0, "sql"), "executescript": (89, 0, "sql_script"),
    "raw": (89, 0, "raw_query"), "mogrify": (89, 0, "query"), "fetch_all": (89, 0, "query"), "fetch_one": (89, 0, "query"),
    "fetchrow": (89, 0, "query"), "fetchval": (89, 0, "query"),
    "save": (22, 0, "dst"),
}
# Methods that open or change a file, when called on a value built as a path.
PATH_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes", "open", "unlink", "rmdir", "iterdir", "mkdir"}
PATH_CONSTRUCTORS = {"pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "Path", "PurePath"}
PATH_JOINERS = {"os.path.join", "posixpath.join", "ntpath.join"}

# qualified function -> sanitiser label
SANITIZERS = {
    "html.escape": "html_escape", "markupsafe.escape": "html_escape", "flask.escape": "html_escape",
    "django.utils.html.escape": "html_escape", "django.utils.html.conditional_escape": "html_escape",
    "bleach.clean": "html_escape", "cgi.escape": "html_escape", "xml.sax.saxutils.escape": "html_escape_nq",
    "django.utils.html.strip_tags": "html_escape_nq", "django.utils.text.slugify": "allowlist",
    "django.utils.text.get_valid_filename": "path_base", "django.utils.encoding.escape_uri_path": "html_escape",
    "urllib.parse.quote": "html_escape", "urllib.parse.quote_plus": "html_escape", "urllib.parse.urlencode": "html_escape",
    "shlex.quote": "shell_arg", "pipes.quote": "shell_arg",
    "werkzeug.utils.secure_filename": "path_base", "os.path.basename": "path_base", "werkzeug.security.safe_join": "path_base",
    "flask.helpers.safe_join": "path_base", "flask.safe_join": "path_base",
    "pymysql.converters.escape_string": "sql_escape", "MySQLdb.escape_string": "sql_escape", "pymysql.escape_string": "sql_escape",
    "psycopg2.sql.Literal": "bound", "psycopg2.sql.Identifier": "bound",
    "os.path.realpath": "resolved", "os.path.abspath": "resolved", "os.path.normpath": "resolved",
}
SANITIZER_METHODS = {"escape_string": "sql_escape", "resolve": "resolved", "absolute": "resolved"}
NUMERIC_FUNCS = {"int", "float", "bool", "complex", "abs", "round", "len", "ord", "uuid.UUID", "decimal.Decimal", "Decimal",
                 "UUID", "ipaddress.ip_address", "ipaddress.ip_network"}
# Results that no visitor controls.
KILL_FUNCS = {"django.shortcuts.get_object_or_404", "get_object_or_404", "django.shortcuts.get_list_or_404", "get_list_or_404",
              "django.core.files.storage.default_storage.exists", "flask.url_for", "url_for", "django.urls.reverse", "reverse", "time.time", "uuid.uuid4", "uuid.uuid1",
              "base64.b64encode", "base64.urlsafe_b64encode", "binascii.hexlify", "ast.literal_eval", "isinstance",
              "callable", "hasattr", "id", "hash", "werkzeug.security.generate_password_hash",
              "werkzeug.security.check_password_hash", "flask.abort", "abort", "sys.exit", "exit"}
KILL_PREFIXES = ("hashlib.", "secrets.", "random.", "math.", "logging.", "bcrypt.", "passlib.", "datetime.", "time.", "uuid.")
# Conversions that change the form of a value without making it safe.
PASSTHROUGH_FUNCS = {"base64.b64decode", "base64.urlsafe_b64decode", "binascii.unhexlify", "json.loads", "json.dumps",
                     "urllib.parse.unquote", "urllib.parse.unquote_plus", "urllib.parse.urlparse", "urllib.parse.urljoin",
                     "html.unescape", "zlib.decompress", "codecs.decode", "shlex.split", "textwrap.dedent", "os.path.splitext",
                     "os.path.dirname", "os.fspath", "os.path.expanduser", "os.path.expandvars"}
# Names that return JSON or a page rendered from a template, neither of which is an XSS sink.
JSON_RESPONSES = {"flask.jsonify", "jsonify", "fastapi.responses.JSONResponse", "starlette.responses.JSONResponse",
                  "flask.json.jsonify", "fastapi.responses.ORJSONResponse", "django.http.JsonResponse", "JsonResponse"}
TEMPLATE_RENDERS = {"flask.render_template", "render_template", "django.shortcuts.render", "render", "flask.send_from_directory",
                    "send_from_directory", "fastapi.responses.PlainTextResponse", "starlette.responses.PlainTextResponse",
                    "fastapi.responses.StreamingResponse", "starlette.responses.StreamingResponse", "fastapi.responses.FileResponse"}
HTML_RESPONSES = {"flask.make_response", "make_response", "flask.Response", "werkzeug.wrappers.Response", "Response",
                  "fastapi.responses.HTMLResponse", "starlette.responses.HTMLResponse", "HTMLResponse",
                  "fastapi.responses.Response", "starlette.responses.Response", "django.http.HttpResponse", "HttpResponse"}
NON_HTML_TYPE = re.compile(r"json|plain|csv|octet|pdf|image/|xml\+|javascript", re.I)
PASSTHROUGH_METHODS = {
    "strip", "lstrip", "rstrip", "lower", "upper", "title", "capitalize", "casefold", "swapcase", "replace", "encode", "decode",
    "split", "rsplit", "splitlines", "partition", "rpartition", "join", "format", "format_map", "get", "pop", "copy", "items",
    "values", "keys", "setdefault", "getlist", "to_dict", "zfill", "ljust", "rjust", "center", "translate", "removeprefix",
    "removesuffix", "read", "readline", "readlines", "expandtabs", "dict", "model_dump", "model_dump_json", "json", "_asdict",
    "append", "extend", "add", "update", "insert", "get_json", "getvalue", "geturl", "unquote", "unquote_plus", "urlparse",
}
FETCH_METHODS = {"fetchone", "fetchall", "fetchmany", "first", "all", "one", "scalar", "scalars", "one_or_none", "scalar_one",
                 "mappings", "fetch"}
# Calls whose first argument is a command string.
SUBPROCESS_FUNCS = {"subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
                    "asyncio.create_subprocess_exec"}
LOGGING_METHODS = {"debug", "info", "warning", "warn", "error", "critical", "exception", "log", "print"}

# sanitiser label -> the reason shown when it protects a finding
LABEL_TEXT = {
    "int": "numeric cast or validation",
    "allowlist": "value checked against an allowlist",
    "html_escape": "HTML escaping that fits the output context",
    "html_escape_nq": "HTML escaping that fits the output context",
    "sql_escape": "SQL escaping inside a quoted value",
    "shell_arg": "shlex.quote",
    "path_base": "basename strips directories",
    "path_real": "realpath with a prefix check",
    "bound": "bound query parameter",
    "fixed_url": "fixed URL prefix before the input",
    "non_html": "response isn't HTML",
    "no_shell": "arguments passed as a list, no shell",
}
# Which labels protect which weakness. Context checks happen where they're applied.
PROTECTS = {
    89: {"int", "allowlist", "bound", "sql_escape"},
    79: {"int", "allowlist", "html_escape", "html_escape_nq", "non_html"},
    78: {"int", "allowlist", "shell_arg", "no_shell"},
    22: {"int", "allowlist", "path_base", "path_real"},
    601: {"int", "allowlist", "fixed_url"},
    94: {"int", "allowlist"},
    502: {"allowlist"},
}
SQL_STATEMENT = re.compile(
    r"^\s*\(?\s*(select\b.+?\bfrom\b|insert\s+(or\s+\w+\s+)?into\b|replace\s+into\b|update\b.+?\bset\b|delete\s+from\b)",
    re.I | re.S)
SQL_WRITE_TABLE = re.compile(r"\b(?:insert\s+(?:or\s+\w+\s+)?into|replace\s+into|update)\s+[`\"\[]?(\w+)", re.I)
SQL_READ_TABLE = re.compile(r"\bfrom\s+[`\"\[]?(\w+)|\bjoin\s+[`\"\[]?(\w+)", re.I)
UNSAFE_REGEX_CHARS = set("'\"<>/\\;&|`$(){}%# ")
SAFE_REDIRECT_PREFIX = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://[^/]+/|/[^/\\])")

# Django form fields that parse their input into a number, date or choice before the view sees it.
TYPED_FORM_FIELDS = {"IntegerField", "FloatField", "DecimalField", "BooleanField", "NullBooleanField", "ChoiceField", "TypedChoiceField",
                     "MultipleChoiceField", "DateField", "DateTimeField", "TimeField", "DurationField", "UUIDField", "SlugField",
                     "ModelChoiceField", "ModelMultipleChoiceField", "GenericIPAddressField"}

"""OpenAPI documents as FastAPI and similar frameworks write them: everything is a $ref."""
from discovery.injection_points import from_route_map
from discovery.openapi_loader import parse_spec

FASTAPI_SPEC = {
    "openapi": "3.1.0",
    "paths": {
        "/items/{item_id}": {"get": {"parameters": [
            {"name": "item_id", "in": "path", "required": True, "schema": {"type": "integer", "title": "Item Id"}},
            {"$ref": "#/components/parameters/Limit"},
            {"name": "X-Token", "in": "header", "required": True, "schema": {"type": "string"}},
        ]}},
        "/items": {"post": {"requestBody": {"required": True, "content": {"application/json": {
            "schema": {"$ref": "#/components/schemas/ItemCreate"}}}}}},
        "/login": {"post": {"requestBody": {"content": {"application/x-www-form-urlencoded": {
            "schema": {"$ref": "#/components/schemas/Body_login"}}}}}},
        "/pets": {"put": {"requestBody": {"$ref": "#/components/requestBodies/Pet"}}},
    },
    "components": {
        "parameters": {"Limit": {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 10}}},
        "requestBodies": {"Pet": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}}},
        "schemas": {
            "Base": {"type": "object", "required": ["owner"], "properties": {"owner": {"type": "string"}}},
            "ItemCreate": {
                "allOf": [{"$ref": "#/components/schemas/Base"}],
                "required": ["name", "qty"],
                "properties": {
                    "name": {"type": "string", "example": "widget"},
                    "qty": {"type": "integer", "minimum": 1},
                    "note": {"type": "string"},
                    "kind": {"type": "string", "enum": ["a", "b"]},
                    "ref": {"type": "string", "format": "uuid"},
                    "tags": {"type": "array", "items": {"type": "string"}},
                    "address": {"$ref": "#/components/schemas/Address"},
                    "id": {"type": "integer", "readOnly": True},
                },
            },
            "Address": {"type": "object", "properties": {"city": {"type": "string"}}},
            "Body_login": {"type": "object", "required": ["username", "password"],
                           "properties": {"username": {"type": "string"}, "password": {"type": "string"}}},
            "Pet": {"type": "object", "properties": {"name": {"type": "string"}, "friend": {"$ref": "#/components/schemas/Pet"}}},
        },
    },
}


def routes():
    return {(r["method"], r["path"]): r for r in parse_spec(FASTAPI_SPEC)}


def shape(route):
    return {(p["name"], p["location"]): p["type"] for p in route["params"]}


def test_refs_to_parameters_and_bodies_are_followed():
    r = routes()
    assert shape(r[("GET", "/items/{item_id}")]) == {("item_id", "path"): "integer", ("limit", "query"): "integer", ("X-Token", "header"): "string"}
    assert ("name", "json") in shape(r[("POST", "/items")])
    assert ("name", "json") in shape(r[("PUT", "/pets")])


def test_allof_is_merged_and_awkward_fields_are_left_out():
    shape_of_items = shape(routes()[("POST", "/items")])
    assert ("owner", "json") in shape_of_items                       # from the allOf base
    assert ("tags", "json") not in shape_of_items                    # an array can't be a flat field
    assert ("address", "json") not in shape_of_items                 # nor can an object
    assert ("id", "json") not in shape_of_items                      # read-only: the server sets it
    assert shape_of_items[("kind", "json")] == "enum" and shape_of_items[("ref", "json")] == "uuid"


def test_a_schema_that_refers_to_itself_does_not_loop():
    assert shape(routes()[("PUT", "/pets")]) == {("name", "json"): "string"}


def test_required_fields_travel_with_the_one_under_test_with_values_of_the_right_type():
    fields = {f["name"]: f["value"] for f in routes()[("POST", "/items")]["fields"]}
    assert fields == {"name": "widget", "qty": 1, "owner": "1"}
    form = {f["name"] for f in routes()[("POST", "/login")]["fields"]}
    assert form == {"username", "password"}


def test_required_path_header_and_query_values_are_filled_in():
    fields = {f["name"]: (f["value"], f["location"]) for f in routes()[("GET", "/items/{item_id}")]["fields"]}
    assert fields["item_id"] == (1, "path") and fields["X-Token"] == ("1", "header")


def test_injection_points_get_siblings_in_the_body_and_the_type():
    points = from_route_map(parse_spec(FASTAPI_SPEC), "http://127.0.0.1:9")
    created = {p.param: p for p in points if p.route_template == "/items" and p.method == "POST"}
    name = created["name"]
    assert name.body_template == {"qty": 1, "owner": "1"} and name.param_location.value == "json"
    assert created["qty"].meta["type"] == "integer"
    path_point = next(p for p in points if p.param == "item_id")
    assert path_point.meta["type"] == "integer"


def test_typed_parameters_are_skipped_and_counted():
    import asyncio

    from core.models import InjectionPoint, ParamLocation
    from scanners.probe_runner import run_probes
    from tests.test_any_app import RecordingProbe, make_rm

    typed = InjectionPoint("GET", "http://127.0.0.1:9/items/{id}", "/items/{id}", "id", ParamLocation.PATH, meta={"type": "integer"})
    free = InjectionPoint("GET", "http://127.0.0.1:9/search", "/search", "q", ParamLocation.QUERY)

    async def go():
        rm, probe, coverage = make_rm(), RecordingProbe(), {}
        try:
            await run_probes(rm, [typed, free], {}, probes=[probe], coverage=coverage)
        finally:
            await rm.aclose()
        return probe, coverage

    probe, coverage = asyncio.run(go())
    assert [call[0] for call in probe.calls] == ["q"]
    assert coverage["pairs_skipped_typed"] == 1 and coverage["points_tested"] == 2


def test_delete_endpoints_are_skipped_unless_allowed():
    import asyncio

    from core.models import InjectionPoint, ParamLocation
    from scanners.probe_runner import run_probes
    from tests.test_any_app import RecordingProbe, make_rm

    delete = InjectionPoint("DELETE", "http://127.0.0.1:9/items/{id}", "/items/{id}", "id", ParamLocation.PATH)
    get = InjectionPoint("GET", "http://127.0.0.1:9/search", "/search", "q", ParamLocation.QUERY)

    async def go(skip):
        rm, probe, coverage = make_rm(), RecordingProbe(), {}
        try:
            await run_probes(rm, [delete, get], {}, probes=[probe], coverage=coverage, skip_methods=skip)
        finally:
            await rm.aclose()
        return probe, coverage

    probe, coverage = asyncio.run(go({"DELETE"}))
    assert [c[0] for c in probe.calls] == ["q"] and coverage["pairs_skipped_destructive"] == 1
    probe, coverage = asyncio.run(go(set()))
    assert sorted(c[0] for c in probe.calls) == ["id", "q"]


def test_a_marker_written_through_an_api_is_found_where_it_is_shown():
    import asyncio
    import socket
    import threading
    import time

    from flask import Flask, jsonify, request

    from core.models import InjectionPoint, ParamLocation
    from scanners.stored_marker import check_persistence, submit_point_markers
    from tests.test_any_app import make_rm

    store = []
    flask_app = Flask("stored")

    @flask_app.route("/api/notes", methods=["POST"])
    def add():
        store.append((request.get_json(silent=True) or {}).get("body", ""))
        return jsonify(status="saved")

    @flask_app.route("/api/notes", methods=["GET"])
    def show():
        return "<ul>" + "".join(f"<li>{b}</li>" for b in store) + "</ul>"

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    threading.Thread(target=lambda: flask_app.run(host="127.0.0.1", port=port, use_reloader=False), daemon=True).start()
    time.sleep(0.4)
    base = f"http://127.0.0.1:{port}"
    points = [
        InjectionPoint("POST", f"{base}/api/notes", "/api/notes", "body", ParamLocation.JSON),
        InjectionPoint("POST", f"{base}/api/notes", "/api/notes", "count", ParamLocation.JSON, meta={"type": "integer"}),
        InjectionPoint("GET", f"{base}/api/notes", "/api/notes", "q", ParamLocation.QUERY),
    ]

    async def go():
        rm = make_rm()
        try:
            submissions = await submit_point_markers(rm, points)
            return submissions, await check_persistence(rm, submissions, sorted({p.baseline_url for p in points if p.method == "GET"}))
        finally:
            await rm.aclose()

    submissions, findings = asyncio.run(go())
    assert [s.field for s in submissions] == ["body"]                 # the integer field can't hold a marker
    assert [(f.cwe, f.method, f.param, f.param_location) for f in findings] == [("CWE-79", "POST", "body", "json")]


def test_a_marker_echoed_in_json_is_not_stored_xss():
    import asyncio
    import socket
    import threading
    import time

    from flask import Flask, jsonify, request

    from core.models import InjectionPoint, ParamLocation
    from scanners.stored_marker import check_persistence, submit_point_markers
    from tests.test_any_app import make_rm

    store = []
    flask_app = Flask("jsonstore")

    @flask_app.route("/api/notes", methods=["POST"])
    def add():
        store.append((request.get_json(silent=True) or {}).get("body", ""))
        return jsonify(status="saved")

    @flask_app.route("/api/notes", methods=["GET"])
    def show():
        return jsonify(store)

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    threading.Thread(target=lambda: flask_app.run(host="127.0.0.1", port=port, use_reloader=False), daemon=True).start()
    time.sleep(0.4)
    base = f"http://127.0.0.1:{port}"
    points = [InjectionPoint("POST", f"{base}/api/notes", "/api/notes", "body", ParamLocation.JSON)]

    async def go():
        rm = make_rm()
        try:
            submissions = await submit_point_markers(rm, points)
            return submissions, await check_persistence(rm, submissions, [f"{base}/api/notes"])
        finally:
            await rm.aclose()

    submissions, findings = asyncio.run(go())
    assert len(submissions) == 1 and findings == []


def test_a_number_used_without_quotes_is_found_and_a_cast_number_is_not():
    import asyncio
    import socket
    import sqlite3
    import threading
    import time

    from flask import Flask, request

    from core.models import InjectionPoint, ParamLocation
    from scanners.probes.sqli import SqliProbe
    from tests.test_any_app import make_rm

    flask_app = Flask("numeric")

    @flask_app.route("/raw/<id>")
    def raw(id):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t (id INTEGER)")
        return str(conn.execute("SELECT * FROM t WHERE id = " + id).fetchall())

    @flask_app.route("/cast/<id>")
    def cast(id):
        return str(int(id))

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    threading.Thread(target=lambda: flask_app.run(host="127.0.0.1", port=port, use_reloader=False), daemon=True).start()
    time.sleep(0.4)

    async def probe(path):
        point = InjectionPoint("GET", f"http://127.0.0.1:{port}{path}/{{id}}", f"{path}/{{id}}", "id", ParamLocation.PATH, seed_value="7")
        rm = make_rm()
        try:
            return await SqliProbe().detect(rm, point, None)
        finally:
            await rm.aclose()

    found = asyncio.run(probe("/raw"))
    assert [f.technique for f in found] == ["error-differential"]
    assert asyncio.run(probe("/cast")) == []

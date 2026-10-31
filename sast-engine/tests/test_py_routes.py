"""Route extraction for Python web apps: Flask and FastAPI."""
import textwrap

import pytest

from sast.lang.python.project import Project
from sast.lang.python.routes import extract


def write(root, files):
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(body))


def routes_of(root, base_path=""):
    return extract(Project(str(root)), base_path)


def by_path(route_map):
    return route_map.routes


FLASK_APP = {
    "app/__init__.py": """
        from flask import Flask
        from .orders import bp as orders_bp
        from .products import products

        def create_app():
            app = Flask(__name__)
            app.register_blueprint(orders_bp, url_prefix="/api/orders")
            app.register_blueprint(products)
            return app
    """,
    "app/orders.py": """
        from flask import Blueprint, request
        bp = Blueprint("orders", __name__, url_prefix="/ignored")

        @bp.route("/")
        def list_orders():
            return "ok"

        @bp.route("/<int:order_id>", methods=["GET", "DELETE"])
        def one(order_id):
            return str(order_id)

        @bp.post("/<order_ref>/note")
        def note(order_ref):
            return request.form["text"]
    """,
    "app/products.py": """
        from flask import Blueprint
        from flask.views import MethodView
        products = Blueprint("products", __name__, url_prefix="/products")

        class Items(MethodView):
            def get(self):
                return "list"
            def post(self):
                return "made"

        products.add_url_rule("/items", view_func=Items.as_view("items"))

        @products.route("/<path:name>/")
        def file(name):
            return name
    """,
}


def test_flask_blueprints_prefixes_and_converters(tmp_path):
    write(tmp_path, FLASK_APP)
    routes = by_path(routes_of(tmp_path))
    assert set(routes) == {"/api/orders/", "/api/orders/{order_id}", "/api/orders/{order_ref}/note", "/products/items",
                           "/products/{name}/"}
    assert routes["/api/orders/{order_id}"].methods == {"GET", "DELETE"}
    assert routes["/api/orders/{order_ref}/note"].methods == {"POST"}
    assert routes["/products/items"].methods == {"GET", "POST"}
    assert routes["/api/orders/"].aliases == ["/api/orders"]  # Flask redirects the slashless form


def test_register_blueprint_prefix_replaces_the_blueprints_own(tmp_path):
    write(tmp_path, FLASK_APP)
    assert not any(path.startswith("/ignored") for path in by_path(routes_of(tmp_path)))


def test_flask_path_parameters_and_numeric_converters(tmp_path):
    write(tmp_path, FLASK_APP)
    route_map = routes_of(tmp_path)
    handlers = {h.fd.label: h for h in route_map.handlers}
    assert handlers["one"].seeds["order_id"].numeric is True
    assert handlers["note"].seeds["order_ref"].numeric is False
    assert [p.to_json() for p in route_map.routes["/api/orders/{order_id}"].required.values()] == [{"name": "order_id", "location": "path", "type": "validated"}]  # <int:...> is parsed before the handler runs


def test_base_path_is_prepended(tmp_path):
    write(tmp_path, FLASK_APP)
    assert "/shop/api/orders/{order_id}" in by_path(routes_of(tmp_path, "/shop"))


def test_handler_lines_cover_the_decorators(tmp_path):
    write(tmp_path, {"a.py": """
        from flask import Flask
        app = Flask(__name__)

        @app.route("/x")
        def x():
            return "1"
    """})
    route = by_path(routes_of(tmp_path))["/x"]
    assert (route.start_line, route.end_line) == (5, 7)
    assert route.handler_function == "x"


FASTAPI_APP = {
    "main.py": """
        from fastapi import FastAPI
        from routers import items

        app = FastAPI()
        app.include_router(items.router, prefix="/v1")
    """,
    "routers/items.py": """
        from typing import Optional, Annotated
        from fastapi import APIRouter, Depends, Header, Query, Request
        from pydantic import BaseModel
        from deps import current_user

        router = APIRouter(prefix="/items")

        class Address(BaseModel):
            city: str

        class ItemIn(BaseModel):
            name: str
            qty: int
            note: Optional[str] = None
            ship_to: Address

        @router.get("/{item_id}")
        def read(item_id: int, q: str = None, size: int = 10, user=Depends(current_user)):
            return {}

        @router.post("")
        async def create(item: ItemIn, x_token: str = Header(...), request: Request = None):
            return {}

        @router.get("/search/{term}")
        def search(term: str, tag: Annotated[str, Query(alias="t")] = "", limit: Annotated[int, Query()] = 5):
            return {}
    """,
    "deps.py": """
        from fastapi import Cookie, Header
        def current_user(session: str = Cookie(None), x_api_key: str = Header(...)):
            return None
    """,
}


def test_fastapi_router_prefixes_stack(tmp_path):
    write(tmp_path, FASTAPI_APP)
    routes = by_path(routes_of(tmp_path))
    assert set(routes) == {"/v1/items/{item_id}", "/v1/items", "/v1/items/search/{term}"}
    assert routes["/v1/items"].methods == {"POST"}
    assert "/v1/items/" in routes["/v1/items"].aliases


def params_of(route):
    return sorted((p["name"], p["location"]) for p in route.to_json()["params"])


def test_fastapi_parameter_binding(tmp_path):
    write(tmp_path, FASTAPI_APP)
    routes = by_path(routes_of(tmp_path))
    # `user=Depends(current_user)` isn't an input itself, but the dependency reads a cookie and a header.
    assert params_of(routes["/v1/items/{item_id}"]) == sorted([("item_id", "path"), ("q", "query"), ("size", "query"),
                                                               ("session", "cookie"), ("x-api-key", "header")])
    assert params_of(routes["/v1/items"]) == sorted([("name", "json"), ("qty", "json"), ("note", "json"), ("city", "json"),
                                                      ("x-token", "header")])
    assert params_of(routes["/v1/items/search/{term}"]) == sorted([("term", "path"), ("t", "query"), ("limit", "query")])


def test_fastapi_numeric_and_required(tmp_path):
    write(tmp_path, FASTAPI_APP)
    route_map = routes_of(tmp_path)
    handlers = {h.fd.label: h for h in route_map.handlers}
    assert handlers["read"].seeds["item_id"].numeric is True
    assert handlers["read"].seeds["q"].numeric is False
    assert handlers["create"].seeds["item"].fields["qty"].numeric is True
    required = {(p["name"], p["location"]) for p in route_map.routes["/v1/items"].to_json()["required_params"]}
    assert ("name", "json") in required and ("note", "json") not in required and ("x-token", "header") in required


def test_unrelated_decorators_are_not_routes(tmp_path):
    write(tmp_path, {"a.py": """
        import functools
        cache = {}
        def memo(f):
            return f
        @memo
        def not_a_route():
            return 1
        @cache.get("/x")
        def odd():
            return 2
    """})
    assert by_path(routes_of(tmp_path)) == {}


def test_syntax_errors_are_recorded_not_fatal(tmp_path):
    write(tmp_path, {"good.py": "x = 1\n", "bad.py": "def (:\n"})
    project = Project(str(tmp_path))
    assert project.syntax_errors == ["bad.py"] and "good.py" in project.files


def test_routes_declared_in_an_openapi_document_are_found(tmp_path):
    write(tmp_path, {
        "app.py": """
            import connexion
            app = connexion.App(__name__, specification_dir="./specs")
            app.add_api("spec.yml", base_path="/v1")
        """,
        "views/users.py": """
            from flask import request

            def get_user(username, verbose=False):
                return {}

            def create(body):
                return {}
        """,
        "specs/spec.yml": """
            openapi: 3.0.1
            paths:
              /users/{username}:
                get:
                  operationId: views.users.get_user
                  parameters:
                    - {name: username, in: path, required: true, schema: {type: string}}
                    - {name: verbose, in: query, schema: {type: boolean}}
              /users:
                post:
                  operationId: views.users.create
                  requestBody:
                    content:
                      application/json:
                        schema: {$ref: '#/components/schemas/NewUser'}
            components:
              schemas:
                NewUser:
                  type: object
                  required: [name]
                  properties:
                    name: {type: string}
                    age: {type: integer}
        """,
    })
    route_map = routes_of(tmp_path)
    assert set(route_map.routes) == {"/v1/users/{username}", "/v1/users"}
    handlers = {h.fd.label: h for h in route_map.handlers}
    assert handlers["get_user"].framework == "openapi"
    assert handlers["get_user"].seeds["username"].numeric is False and handlers["get_user"].seeds["verbose"].numeric is True
    assert sorted(handlers["create"].seeds["body"].fields) == ["age", "name"]
    shape = {(p["name"], p["location"]) for p in route_map.routes["/v1/users"].to_json()["params"]}
    assert shape == {("name", "json"), ("age", "json")}

"""fastshop: a small, deliberately vulnerable FastAPI app, for testing the scanners on a typed API with an
OpenAPI document and no debug output. Run it on loopback only:

    uvicorn main:app --host 127.0.0.1 --port 8091
"""
import os
import sqlite3
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, FastAPI, Header, Query
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "fast.db")
API_TOKEN = "fastshop-token-4f9a2c71e8b0"

app = FastAPI(title="fastshop")
router = APIRouter(prefix="/api/v1")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def setup():
    conn = db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, item_id INTEGER, body TEXT);
    """)
    if not conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]:
        conn.execute("INSERT INTO items (name, price) VALUES ('Hammer', 12.5)")
        conn.execute("INSERT INTO items (name, price) VALUES ('Anvil', 99.5)")
    conn.commit()
    conn.close()


setup()


class NoteIn(BaseModel):
    body: str
    author: Optional[str] = None


class ItemIn(BaseModel):
    name: str
    price: float = 1.0


def current_user(x_api_key: Annotated[str, Header()] = ""):
    return {"key": x_api_key}


@router.get("/items")
def list_items(sort: str = "name", limit: int = 10):
    column = {"name": "name", "price": "price"}.get(sort, "name")
    rows = db().execute(f"SELECT id, name, price FROM items ORDER BY {column} LIMIT {limit}").fetchall()
    return [dict(r) for r in rows]


@router.get("/items/search")
def search_items(q: str = Query("")):
    rows = db().execute(f"SELECT id, name, price FROM items WHERE name LIKE '%{q}%'").fetchall()
    return [dict(r) for r in rows]


@router.get("/items/{item_id}")
def get_item(item_id: int):
    row = db().execute("SELECT id, name, price FROM items WHERE id = ?", (item_id,)).fetchone()
    return dict(row) if row else JSONResponse({"detail": "not found"}, status_code=404)


@router.post("/items")
def create_item(item: ItemIn, user: dict = Depends(current_user)):
    conn = db()
    conn.execute(f"INSERT INTO items (name, price) VALUES ('{item.name}', {item.price})")
    conn.commit()
    return {"status": "created"}


@router.post("/items/{item_id}/notes")
def add_note(item_id: int, note: NoteIn):
    conn = db()
    conn.execute("INSERT INTO notes (item_id, body) VALUES (?, ?)", (item_id, note.body))
    conn.commit()
    return {"status": "saved"}


@router.get("/items/{item_id}/notes", response_class=HTMLResponse)
def show_notes(item_id: int):
    rows = db().execute("SELECT body FROM notes WHERE item_id = ?", (item_id,)).fetchall()
    return "<ul>" + "".join(f"<li>{r['body']}</li>" for r in rows) + "</ul>"


@router.get("/hello", response_class=HTMLResponse)
def hello(name: str = "world"):
    return f"<h1>Hello {name}</h1>"


@router.get("/greeting")
def greeting(name: str = "world"):
    return {"greeting": f"Hello {name}"}


@router.get("/files")
def read_file(name: str):
    return FileResponse(os.path.join(BASE, "files", name))


@router.get("/go")
def go(url: str = "/"):
    return RedirectResponse(url)


app.include_router(router)

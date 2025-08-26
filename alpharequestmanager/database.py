# File: alpharequestmanager/database.py
import json
import os
import sqlite3
from datetime import datetime

from .models import Ticket, RequestStatus
from .logger import logger

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "tickets.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    logger.info("initializing database")
    conn = get_connection()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS tickets (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        title        TEXT    NOT NULL,
        description  TEXT    NOT NULL,
        owner_id     TEXT    NOT NULL,
        owner_name   TEXT    NOT NULL,
        owner_info   TEXT    NOT NULL,
        comment      TEXT    NOT NULL,
        status       TEXT    NOT NULL,
        created_at   TEXT    NOT NULL,
        ninja_metadata TEXT  DEFAULT NULL
    );
    """)

    conn.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key         TEXT PRIMARY KEY,
        value_json  TEXT NOT NULL,
        updated_at  TEXT NOT NULL
    );
    """)
    conn.commit()
    conn.close()


def insert_ticket(title: str,
                  description: str,
                  owner_id: str,
                  owner_name: str,
                  owner_info,
                  ninja_metadata: str | None = None) -> int:
    comment = ""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.utcnow().isoformat()

    c.execute("""
        INSERT INTO tickets
            (title, description, owner_id, owner_name, comment, status, created_at, owner_info, ninja_metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        title,
        description,
        owner_id,
        owner_name,
        comment,
        RequestStatus.pending.value,
        now,
        owner_info,
        ninja_metadata
    ))
    conn.commit()
    ticket_id = c.lastrowid
    conn.close()
    return ticket_id


def list_all_tickets() -> list[Ticket]:
    conn = get_connection()
    rows = conn.execute("""
                        SELECT id,
                               title,
                               description,
                               owner_id,
                               owner_name,
                               comment,
                               status,
                               created_at,
                               owner_info,
                               ninja_metadata
                        FROM tickets
                        ORDER BY created_at DESC
                        """).fetchall()
    conn.close()
    return [Ticket.from_row(r) for r in rows]

def list_pending_tickets() -> list[Ticket]:
    conn = get_connection()
    rows = conn.execute("""
        SELECT id, title, description, owner_id, owner_name, comment, status, created_at, owner_info, ninja_metadata
        FROM tickets
        WHERE status = ?
    """, (RequestStatus.pending.value,)).fetchall()
    conn.close()
    return [Ticket.from_row(r) for r in rows]

def list_tickets_by_owner(owner_id: str) -> list[Ticket]:
    conn = get_connection()
    rows = conn.execute("""
        SELECT id, title, description, owner_id, owner_name, comment, status, created_at, owner_info
        FROM tickets
        WHERE owner_id = ?
        ORDER BY created_at DESC
    """, (owner_id,)).fetchall()
    conn.close()
    return [Ticket.from_row(r) for r in rows]

def update_ticket(ticket_id: int, **fields) -> None:
    """
    Aktualisiert einen oder mehrere Spalten des Tickets mit id=ticket_id.
    Beispiel:
        update_ticket(5, status="approved")
        update_ticket(7, status="rejected", owner_name="Max Mustermann")
    """
    # Erlaubte Spalten
    allowed = {"title","description","owner_id","owner_name", "comment","status","created_at"}
    # Filter ungültiger keys
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return

    # Dynamisch SET-Klausel bauen
    set_clause = ", ".join(f"{col}=?" for col in updates)
    params = list(updates.values()) + [ticket_id]
    conn = get_connection()
    c = conn.cursor()
    c.execute(f"""
        UPDATE tickets
        SET {set_clause}
        WHERE id = ?
    """, params)
    conn.commit()
    conn.close()






def _now_iso():
    return datetime.utcnow().isoformat()

def settings_init_defaults(defaults: dict[str, object]) -> None:
    """
    Legt Default-Keys an, wenn sie fehlen; überschreibt NICHT existierende Werte.
    """
    if not defaults:
        return
    conn = get_connection()
    cur = conn.cursor()
    for k, v in defaults.items():
        cur.execute("""
            INSERT INTO settings (key, value_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO NOTHING
        """, (k, json.dumps(v), _now_iso()))
    conn.commit()
    conn.close()

def settings_get(key: str, default: object | None = None) -> object:
    conn = get_connection()
    row = conn.execute("SELECT value_json FROM settings WHERE key = ?", (key,)).fetchone()
    conn.close()
    if not row:
        return default
    return json.loads(row["value_json"])

def settings_set(key: str, value: object) -> None:
    conn = get_connection()
    conn.execute("""
        INSERT INTO settings (key, value_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value_json = excluded.value_json,
            updated_at = excluded.updated_at
    """, (key, json.dumps(value), _now_iso()))
    conn.commit()
    conn.close()

def settings_all() -> dict[str, object]:
    conn = get_connection()
    rows = conn.execute("SELECT key, value_json FROM settings").fetchall()
    conn.close()
    return {r["key"]: json.loads(r["value_json"]) for r in rows}


def update_ticket_metadata(ticket_id: int, ninja_ticket_id: int | None = None, synced_at: str | None = None) -> None:
    """
    Aktualisiert die NinjaOne-Metadaten eines Tickets.
    Speichert JSON wie {"ninja_ticket_id": 1234, "synced_at": "..."} in ninja_metadata.
    """
    conn = get_connection()
    cur = conn.cursor()

    # Existierende Metadaten laden
    row = cur.execute("SELECT ninja_metadata FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    metadata = {}
    if row and row["ninja_metadata"]:
        try:
            metadata = json.loads(row["ninja_metadata"])
        except json.JSONDecodeError:
            metadata = {}

    if ninja_ticket_id is not None:
        metadata["ninja_ticket_id"] = ninja_ticket_id
    if synced_at is not None:
        metadata["synced_at"] = synced_at
    else:
        metadata["synced_at"] = _now_iso()

    cur.execute("UPDATE tickets SET ninja_metadata = ? WHERE id = ?", (json.dumps(metadata), ticket_id))
    conn.commit()
    conn.close()


def get_ticket_metadata(ticket_id: int) -> dict | None:
    """
    Liest die NinjaOne-Metadaten eines Tickets.
    """
    conn = get_connection()
    row = conn.execute("SELECT ninja_metadata FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    conn.close()
    if row and row["ninja_metadata"]:
        try:
            return json.loads(row["ninja_metadata"])
        except json.JSONDecodeError:
            return None
    return None

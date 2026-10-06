from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import aiosqlite

_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id              TEXT PRIMARY KEY,
    created_at      TEXT NOT NULL,
    sender_address  TEXT,
    recipient_address TEXT,
    subject         TEXT,
    source          TEXT NOT NULL,
    client_ip       TEXT,
    eml_path        TEXT NOT NULL,
    overall_score   REAL,
    rating          TEXT,
    results_json    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_sender ON analyses(sender_address);

CREATE TABLE IF NOT EXISTS analysis_chat_messages (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     TEXT NOT NULL,
    analysis_version TEXT NOT NULL,
    role            TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content         TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_chat_analysis_version
    ON analysis_chat_messages(analysis_id, analysis_version, id);
"""


async def init_db(db_path: Path) -> None:
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.executescript(_SCHEMA)
        await conn.commit()


@asynccontextmanager
async def get_db(db_path: Path) -> AsyncIterator[aiosqlite.Connection]:
    conn = await aiosqlite.connect(str(db_path))
    conn.row_factory = aiosqlite.Row
    try:
        yield conn
    finally:
        await conn.close()


async def insert_analysis(conn: aiosqlite.Connection, data: dict) -> None:
    await conn.execute(
        """INSERT INTO analyses
           (id, created_at, sender_address, recipient_address, subject,
            source, client_ip, eml_path, overall_score, rating, results_json)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            data["id"],
            data["created_at"],
            data.get("sender_address"),
            data.get("recipient_address"),
            data.get("subject"),
            data["source"],
            data.get("client_ip"),
            data["eml_path"],
            data.get("overall_score"),
            data.get("rating"),
            data["results_json"],
        ),
    )
    await conn.commit()


async def get_analysis(conn: aiosqlite.Connection, analysis_id: str) -> dict | None:
    cursor = await conn.execute(
        "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return dict(row)


async def list_analyses(
    conn: aiosqlite.Connection, limit: int = 20, offset: int = 0
) -> list[dict]:
    """Return a bounded page of analyses, newest first."""
    limit = max(1, min(int(limit), 100))
    offset = max(0, int(offset))
    cursor = await conn.execute(
        "SELECT * FROM analyses ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    rows = await cursor.fetchall()
    return [dict(r) for r in rows]


async def delete_analysis(
    conn: aiosqlite.Connection, analysis_id: str
) -> dict | None:
    """Delete one analysis row and return it, or ``None`` when absent."""
    cursor = await conn.execute(
        "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
    )
    row = await cursor.fetchone()
    if row is None:
        return None

    await conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    await conn.commit()
    return dict(row)


async def update_analysis(conn: aiosqlite.Connection, data: dict) -> None:
    """Replace the mutable result fields for an existing analysis."""
    cursor = await conn.execute(
        """UPDATE analyses
           SET created_at = ?, sender_address = ?, recipient_address = ?,
               subject = ?, source = ?, client_ip = ?, overall_score = ?,
               rating = ?, results_json = ?
           WHERE id = ?""",
        (
            data["created_at"],
            data.get("sender_address"),
            data.get("recipient_address"),
            data.get("subject"),
            data["source"],
            data.get("client_ip"),
            data.get("overall_score"),
            data.get("rating"),
            data["results_json"],
            data["id"],
        ),
    )
    if cursor.rowcount != 1:
        raise KeyError(f"Analysis not found: {data['id']}")
    await conn.commit()


async def delete_all_analyses(conn: aiosqlite.Connection) -> list[dict]:
    """Delete all analysis rows and return their metadata for file cleanup."""
    cursor = await conn.execute("SELECT * FROM analyses")
    rows = [dict(row) for row in await cursor.fetchall()]
    await conn.execute("DELETE FROM analyses")
    await conn.commit()
    return rows


async def list_chat_messages(
    conn: aiosqlite.Connection,
    analysis_id: str,
    analysis_version: str,
    limit: int = 20,
) -> list[dict]:
    """Return the newest bounded chat messages in chronological order."""
    limit = max(1, min(int(limit), 50))
    cursor = await conn.execute(
        """SELECT role, content, created_at
           FROM analysis_chat_messages
           WHERE analysis_id = ? AND analysis_version = ?
           ORDER BY id DESC LIMIT ?""",
        (analysis_id, analysis_version, limit),
    )
    rows = [dict(row) for row in await cursor.fetchall()]
    return list(reversed(rows))


async def insert_chat_message(
    conn: aiosqlite.Connection,
    analysis_id: str,
    analysis_version: str,
    role: str,
    content: str,
    created_at: str,
) -> None:
    """Persist one bounded chat message."""
    if role not in {"user", "assistant"}:
        raise ValueError("Invalid chat role")
    await conn.execute(
        """INSERT INTO analysis_chat_messages
           (analysis_id, analysis_version, role, content, created_at)
           VALUES (?, ?, ?, ?, ?)""",
        (analysis_id, analysis_version, role, content[:10000], created_at),
    )
    await conn.commit()


async def clear_chat_messages(
    conn: aiosqlite.Connection, analysis_id: str, analysis_version: str | None = None
) -> None:
    """Clear chat for one analysis, optionally only one revision."""
    if analysis_version is None:
        await conn.execute(
            "DELETE FROM analysis_chat_messages WHERE analysis_id = ?",
            (analysis_id,),
        )
    else:
        await conn.execute(
            """DELETE FROM analysis_chat_messages
               WHERE analysis_id = ? AND analysis_version = ?""",
            (analysis_id, analysis_version),
        )
    await conn.commit()

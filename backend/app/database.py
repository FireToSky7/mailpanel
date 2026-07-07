from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Generator

import pymysql
from pymysql.cursors import DictCursor

from app.config import DatabaseConfig, get_config


@contextmanager
def db_connection(cfg: DatabaseConfig) -> Generator[pymysql.connections.Connection, None, None]:
    conn = pymysql.connect(
        host=cfg.host,
        port=cfg.port,
        user=cfg.user,
        password=cfg.password,
        database=cfg.database,
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=True,
    )
    try:
        yield conn
    finally:
        conn.close()


def panel_conn():
    return db_connection(get_config().database)


def vmail_conn():
    return db_connection(get_config().vmail_database)


def amavisd_conn():
    return db_connection(get_config().amavisd_database)


def fetch_all(conn, query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with conn.cursor() as cur:
        cur.execute(query, params)
        return list(cur.fetchall())


def fetch_one(conn, query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    rows = fetch_all(conn, query, params)
    return rows[0] if rows else None


def execute(conn, query: str, params: tuple[Any, ...] = ()) -> int:
    with conn.cursor() as cur:
        return cur.execute(query, params)

from __future__ import annotations

import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_config
from app.routers import api_router, auth_router
from app.services.log_collector import LogCollector, ensure_bootstrap_admin

FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
_collector_thread: threading.Thread | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _collector_thread
    try:
        ensure_bootstrap_admin()
    except Exception:
        pass
    cfg = get_config()
    if cfg.log_collector.enabled:
        collector = LogCollector()

        def _run():
            collector.run_loop()

        _collector_thread = threading.Thread(target=_run, daemon=True, name="log-collector")
        _collector_thread.start()
    yield


app = FastAPI(title="MailPanel", version="0.1.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(api_router.router)

if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")


@app.get("/")
def index():
    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"message": "MailPanel API is running. Build frontend: cd frontend && npm run build"}


@app.get("/{path:path}")
def spa_fallback(path: str):
    if path.startswith("api/"):
        return {"detail": "Not found"}
    index_file = FRONTEND_DIST / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {"detail": "Frontend not built"}

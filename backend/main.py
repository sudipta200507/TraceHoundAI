"""TraceHoundAI FastAPI entrypoint — tool health, safety, and scan orchestration."""

from fastapi import FastAPI

from backend.app.api.routes.scans import router as scans_router
from backend.app.api.routes.system import router as system_router

app = FastAPI(title="TraceHoundAI")


@app.get("/health")
def health():
    return {"status": "ok"}


app.include_router(system_router)
app.include_router(scans_router)

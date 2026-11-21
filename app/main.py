"""SecureScan AI - FastAPI application entry point."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from .api import auth, scans, system, users
from .config import APP_NAME, APP_VERSION, STATIC_DIR, settings
from .database import init_db
from .services import runner

logging.basicConfig(level=getattr(logging, settings.log_level, logging.INFO),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("securescan")

CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; "
       "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    recovered = runner.recover_interrupted()
    if recovered:
        log.warning("Marked %s interrupted scan(s) as failed", recovered)
    log.info("%s %s started", APP_NAME, APP_VERSION)
    yield


app = FastAPI(title=APP_NAME, version=APP_VERSION, lifespan=lifespan, docs_url=None, redoc_url=None,
              openapi_url=None)

if settings.allowed_origins:
    app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "PATCH", "DELETE"], allow_headers=["Authorization", "Content-Type"])


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    limit = (settings.max_upload_mb + 2) * 1024 * 1024 if request.url.path == "/api/scans/source" else 1024 * 1024
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > limit:
        return JSONResponse({"detail": "The request is too large."}, status_code=413)
    response = await call_next(request)
    h = response.headers
    h["Content-Security-Policy"] = CSP
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.url.scheme == "https":
        h["Strict-Transport-Security"] = "max-age=31536000"
    if request.url.path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
    return response


@app.exception_handler(StarletteHTTPException)
async def http_error(_request: Request, exc: StarletteHTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, exc: RequestValidationError):
    first = exc.errors()[0] if exc.errors() else {}
    field = ".".join(str(p) for p in first.get("loc", [])[1:]) or "request"
    return JSONResponse({"detail": f"Invalid input for '{field}': {first.get('msg', 'invalid value')}."}, status_code=422)


@app.exception_handler(Exception)
async def unhandled(_request: Request, exc: Exception):
    log.exception("Unhandled error: %s", exc.__class__.__name__)
    return JSONResponse({"detail": "Internal server error."}, status_code=500)


for module in (auth, users, scans, system):
    app.include_router(module.router)

app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="web")

"""
Target REST API (Upstream Service).
Spec Reference: §6 System Design & §4 Threat Model.

This module provides a representative target REST application exposing endpoints
with varying resource costs and sensitivity:
- GET /api/v1/resource: Lightweight read endpoint (scraping target).
- POST /api/v1/auth/login: Authentication endpoint (credential stuffing target).
- POST /api/v1/heavy-export: CPU-intensive data export (resource-exhaustion DoS target).
- GET /health: Health check endpoint.
"""

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="Target Upstream REST API", version="0.1.0")


class LoginRequest(BaseModel):
    username: str
    password: str


class ExportRequest(BaseModel):
    query: str
    limit: int = 100


@app.get("/health")
async def health_check():
    """Health check endpoint for upstream service."""
    return {"status": "ok"}


@app.get("/api/v1/resource")
async def get_resource():
    """Lightweight read endpoint simulating typical content endpoint."""
    return {"data": "resource content", "status": "success"}


@app.post("/api/v1/auth/login")
async def login(req: LoginRequest):
    """Authentication endpoint simulating login verification."""
    # Stub authentication verification logic
    if req.username == "admin" and req.password == "secret":
        return {"token": "valid_token"}
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


@app.post("/api/v1/heavy-export")
async def heavy_export(req: ExportRequest):
    """Resource-heavy endpoint simulating database aggregation / report export."""
    return {"export_id": "exp_12345", "query": req.query, "records": req.limit}

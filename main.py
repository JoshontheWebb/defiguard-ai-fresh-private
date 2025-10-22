##section 1##
import logging
import os
import platform
import json
import time
import uuid
from datetime import datetime, timedelta
import secrets
from tempfile import NamedTemporaryFile
from typing import Optional
from fastapi import FastAPI, File, UploadFile, Request, Query, HTTPException, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from web3 import Web3
import stripe
import bcrypt
import sqlite3
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from slither import Slither
from slither.exceptions import SlitherError
from openai import OpenAI
import re
from tenacity import retry, stop_after_attempt, wait_fixed
import uvicorn
from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import BaseModel
from dotenv import load_dotenv
# Ensure logging directory exists (Render-specific)
LOG_DIR = "/opt/render/project/data"
os.makedirs(LOG_DIR, exist_ok=True)
# Initialize logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "debug.log")),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)
# Initialize FastAPI app
app = FastAPI(title="DeFiGuard AI", description="Predictive DeFi Compliance Auditor")
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/templates", StaticFiles(directory="templates"), name="templates")
# HTTP middleware for global request logging
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.debug(f"Incoming request: {request.method} {request.url}, headers={request.headers}, client={request.client.host}")
    response = await call_next(request)
    logger.debug(f"Response: status={response.status_code}, headers={response.headers}")
    return response
# Load environment variables at startup
@app.on_event("startup")
async def startup_event():
    load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))
    required_env_vars = [
        "GROK_API_KEY",
        "INFURA_PROJECT_ID",
        "STRIPE_API_KEY",
        "STRIPE_WEBHOOK_SECRET",
        "STRIPE_PRICE_PRO",
        "STRIPE_PRICE_BEGINNER",
        "STRIPE_PRICE_DIAMOND",
        "STRIPE_METERED_PRICE_DIAMOND",
    ]
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        logger.error(f"Missing critical environment variables: {', '.join(missing_vars)}")
        raise RuntimeError(f"Missing critical environment variables: {', '.join(missing_vars)}")
    # Log specific Stripe price IDs
    stripe_vars = [
        "STRIPE_PRICE_PRO",
        "STRIPE_PRICE_BEGINNER",
        "STRIPE_PRICE_DIAMOND",
        "STRIPE_METERED_PRICE_DIAMOND",
    ]
    for var in stripe_vars:
        value = os.getenv(var)
        logger.info(f"Environment variable {var}: {'set' if value else 'NOT set'}")
# Root endpoint to redirect to /ui
@app.get("/", response_class=RedirectResponse)
async def root():
    logger.info("Root endpoint accessed, redirecting to /ui")
    return RedirectResponse(url="/ui")
# Debug route registration at startup
@app.on_event("startup")
async def log_routes():
    routes = [route.path for route in app.routes]
    logger.info(f"Registered routes: {routes}")
    if "/create-tier-checkout" in routes:
        logger.info("Confirmed: /create-tier-checkout is registered")
    else:
        logger.error("Error: /create-tier-checkout is NOT registered")
# Manual CSRF Protection
async def get_csrf_token(request: Request) -> str:
    try:
        token = request.session.get("csrf_token")
        if not token:
            token = secrets.token_urlsafe(32)
            request.session["csrf_token"] = token
            logger.debug(f"Generated new CSRF token: {token}, session: {request.session}")
        else:
            logger.debug(f"Reusing existing CSRF token: {token}, session: {request.session}")
        return token
    except Exception as e:
        logger.error(f"Failed to get CSRF token: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate CSRF token: {str(e)}")
async def verify_csrf_token(request: Request):
    provided_token = request.headers.get("X-CSRF-Token")
    expected_token = request.session.get("csrf_token")
    logger.debug(f"Verifying CSRF token: Provided={provided_token}, Expected={expected_token}, session: {request.session}")
    if not provided_token or provided_token != expected_token:
        logger.error(f"CSRF validation failed: Provided={provided_token}, Expected={expected_token}")
        raise HTTPException(status_code=403, detail="CSRF token validation failed")
    logger.debug("CSRF token verified successfully")
@app.get("/csrf-token")
async def get_csrf(request: Request):
    try:
        logger.debug(f"Received /csrf-token request from {request.client.host}, headers: {request.headers}, cookies: {request.cookies}, session: {request.session}")
        token = await get_csrf_token(request)
        if not isinstance(token, str):
            logger.error(f"Invalid CSRF token generated: {token}, type={type(token)}")
            raise HTTPException(status_code=500, detail="Failed to generate valid CSRF token")
        logger.info(f"Returning CSRF token: {token}")
        return {"csrf_token": token}
    except Exception as e:
        logger.error(f"CSRF endpoint error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to generate CSRF token: {str(e)}")
# Database setup
DATABASE_URL = "sqlite:////opt/render/project/data/users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    tier = Column(String, default="free")
    has_diamond = Column(Boolean, default=False)
    last_reset = Column(DateTime)
    api_key = Column(String, nullable=True)
    audit_history = Column(String, default="[]")
    stripe_subscription_id = Column(String, nullable=True)
    stripe_subscription_item_id = Column(String, nullable=True)
Base.metadata.create_all(bind=engine)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
# Initialize clients
client = OpenAI(api_key=os.getenv("GROK_API_KEY"))
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")
w3 = Web3(Web3.HTTPProvider(f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}"))
logger.info("Initializing OpenAI and Web3 clients...")
logger.info("Starting client initialization...")
logger.info("OpenAI client created successfully.")
logger.info("Web3 provider initialized.")
logger.info("Clients initialized successfully.")
# Stripe setup
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
stripe.api_key = STRIPE_API_KEY
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
STRIPE_PRICE_PRO = "price_1SKBM0EqXlKjClpjnuZ6R5pi"
STRIPE_PRICE_BEGINNER = "price_1SFoJGEqXlKjClpjj2RZ10bf"
STRIPE_PRICE_DIAMOND = "price_1SFoVMEqXlKjClpjTyRtHJcD"
STRIPE_METERED_PRICE_DIAMOND = "price_1SFpPTEqXlKjClpjeGFNYSgF"
FREE_LIMIT = 3
BEGINNER_LIMIT = 10
PRO_LIMIT = 9999 # Updated from float("inf") to avoid JSON serialization issues
level_map = {
    "free": 0,
    "beginner": 1,
    "pro": 2,
    "diamond": 3
}
class AuditResponse(BaseModel):
    report: dict
    risk_score: str
    overage_cost: Optional[float] = None
AUDIT_SCHEMA = {
    "type": "object",
    "properties": {
        "risk_score": {"type": "number"},
        "issues": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "severity": {"type": "string"},
                    "description": {"type": ["string", "null"]},
                    "fix": {"type": "string"}
                },
                "required": ["type", "severity", "fix"]
            }
        },
        "predictions": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "scenario": {"type": "string"},
                    "impact": {"type": "string"}
                },
                "required": ["scenario", "impact"]
            }
        },
        "recommendations": {"type": "array", "items": {"type": "string"}},
        "remediation_roadmap": {"type": ["string", "null"]},
        "fuzzing_results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "vulnerability": {"type": "string"},
                    "description": {"type": "string"}
                },
                "required": ["vulnerability", "description"]
            }
        }
    },
    "required": ["risk_score", "issues", "predictions", "recommendations"]
}
# Define PROMPT_TEMPLATE for audit endpoint
PROMPT_TEMPLATE = """
Analyze this Solidity code for vulnerabilities and 2025 regulations (MiCA, SEC FIT21).
Context: {context}.
Fuzzing Results: {fuzzing_results}.
Code: {code}.
Protocol Details: {details}.
Tier: {tier}.
Return the analysis in the exact JSON schema provided. For Beginner/Pro, include detailed predictions and recommendations. For Pro, add advanced regulatory insights and fuzzing results. For Diamond add-on, include formal verification, exploit simulation, threat modeling, fuzzing results, and a remediation roadmap.
"""

## Section 2
import os.path
DATA_DIR = "/opt/render/project/data" # Render persistent disk
USAGE_STATE_FILE = os.path.join(DATA_DIR, "usage_state.json")
USAGE_COUNT_FILE = os.path.join(DATA_DIR, "usage_count.txt")
class UsageTracker:
    def __init__(self):
        self.count = 0
        self.last_reset = datetime.now()
        os.makedirs(DATA_DIR, exist_ok=True) # Ensure persistent directory exists
        if os.path.exists(USAGE_STATE_FILE):
            try:
                with open(USAGE_STATE_FILE, "r") as f:
                    state = json.load(f)
                self.last_tier = state.get("last_tier", "free")
                self.last_change_time = datetime.fromisoformat(state.get("last_change_time", datetime.now().isoformat()))
            except Exception as e:
                logger.error(f"Failed to load usage state: {str(e)}")
                self.last_tier = "free"
                self.last_change_time = datetime.now()
        else:
            self.last_tier = "free"
            self.last_change_time = datetime.now()
            self._save_state()
        if os.path.exists(USAGE_COUNT_FILE):
            try:
                with open(USAGE_COUNT_FILE, "r") as f:
                    legacy_count = int(f.read().strip() or 0)
                if legacy_count > self.count:
                    self.count = legacy_count
                    self._save_state()
            except Exception as e:
                logger.error(f"Failed to load usage count: {str(e)}")
        self.size_limits = {"free": 1024 * 1024, "beginner": 1024 * 1024, "pro": 1024 * 1024, "diamond": float("inf")}
        self.feature_flags = {
            "free": {"diamond": False, "predictions": False, "onchain": False, "reports": False, "fuzzing": False, "priority_support": False, "nft_rewards": False},
            "beginner": {"diamond": False, "predictions": True, "onchain": True, "reports": True, "fuzzing": False, "priority_support": True, "nft_rewards": False},
            "pro": {"diamond": True, "predictions": True, "onchain": True, "reports": True, "fuzzing": True, "priority_support": True, "nft_rewards": False},
            "diamond": {"diamond": True, "predictions": True, "onchain": True, "reports": True, "fuzzing": True, "priority_support": True, "nft_rewards": True}
        }
    def calculate_diamond_overage(self, file_size):
        """Calculate progressive overage for Diamond tier files >1MB."""
        if file_size <= 1024 * 1024:
            return 0
        overage_mb = (file_size - 1024 * 1024) / (1024 * 1024)
        total_cost = 0
        if overage_mb <= 10:
            total_cost = overage_mb * 0.50
        else:
            total_cost += 10 * 0.50
            remaining_mb = overage_mb - 10
            if remaining_mb <= 40:
                total_cost += remaining_mb * 1.00
            else:
                total_cost += 40 * 1.00
                remaining_mb -= 40
                if remaining_mb <= 2:
                    total_cost += remaining_mb * 2.00
                else:
                    total_cost += 2 * 2.00
                    total_cost += (remaining_mb - 2) * 5.00
        return round(total_cost * 100)
    def increment(self, file_size, username=None, db: Session = None):
        if username:
            user = db.query(User).filter(User.username == username).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            current_time = datetime.now()
            if user.tier == "free" and (current_time - user.last_reset).days >= 30:
                self.count = 0
                user.last_reset = current_time
                logger.info(f"Reset usage for {username} on free tier after 30 days")
            elif user.tier in ["beginner", "pro"] and (current_time - user.last_reset).days >= 30:
                user.tier = "free"
                user.has_diamond = False
                self.count = 0
                user.last_reset = current_time
                db.commit()
                logger.info(f"Downgraded {username} to free tier due to non-payment")
            if file_size > self.size_limits.get(user.tier, self.size_limits["free"]) and not user.has_diamond:
                overage_cost = self.calculate_diamond_overage(file_size) / 100
                raise HTTPException(
                    status_code=400,
                    detail=f"Access to Diamond audits is only available on Pro tier with Diamond add-on. Upgrade to Pro + Diamond ($200/mo + $50/mo + ${overage_cost:.2f} overage for this file)."
                )
            self.count += 1
            user.last_reset = current_time
            db.commit()
            logger.info(f"UsageTracker incremented to: {self.count} for {username}, current tier: {user.tier}, has_diamond: {user.has_diamond}")
            return self.count
        else:
            current_tier = os.getenv("TIER", "free")
            current_time = datetime.now()
            if current_tier != self.last_tier:
                old_level = level_map.get(self.last_tier, 0)
                new_level = level_map.get(current_tier, 0)
                days_since_change = (current_time - self.last_change_time).days
                if new_level > old_level:
                    logger.info(f"Upgrade detected from {self.last_tier} to {current_tier}, resetting count")
                    self.count = 0
                elif new_level < old_level:
                    if days_since_change > 30:
                        logger.info(f"Downgrade from {self.last_tier} to {current_tier} after 30+ days, resetting count")
                        self.count = 0
                    else:
                        logger.info(f"Downgrade from {self.last_tier} to {current_tier} within 30 days, keeping count")
                self.last_tier = current_tier
                self.last_change_time = current_time
                self._save_state()
            if file_size > self.size_limits[current_tier]:
                overage_cost = self.calculate_diamond_overage(file_size) / 100
                raise HTTPException(
                    status_code=400,
                    detail=f"Access to Diamond audits is only available on Pro tier with Diamond add-on. Upgrade to Pro + Diamond ($200/mo + $50/mo + ${overage_cost:.2f} overage for this file)."
                )
            self.count += 1
            self._save_state()
            limits = {"free": FREE_LIMIT, "beginner": BEGINNER_LIMIT, "pro": PRO_LIMIT, "diamond": PRO_LIMIT}
            if self.count > limits.get(current_tier, FREE_LIMIT):
                raise HTTPException(status_code=403, detail=f"Usage limit exceeded for {current_tier} tier. Limit is {limits.get(current_tier, FREE_LIMIT)}. Upgrade tier.")
            logger.info(f"UsageTracker incremented to: {self.count}, current tier: {current_tier}")
            return self.count
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def _save_state(self):
        state = {
            "count": self.count,
            "last_tier": self.last_tier,
            "last_change_time": self.last_change_time.isoformat()
        }
        try:
            with open(USAGE_STATE_FILE, "w") as f:
                json.dump(state, f)
            with open(USAGE_COUNT_FILE, "w") as f:
                f.write(str(self.count))
        except PermissionError as e:
            logger.error(f"Failed to save usage state: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to save usage state due to permissions")
    def reset_usage(self, username: str = None, db: Session = None):
        try:
            if username:
                user = db.query(User).filter(User.username == username).first()
                if not user:
                    logger.error(f"Reset usage failed: User {username} not found")
                    raise HTTPException(status_code=404, detail=f"User {username} not found")
                self.count = 0
                user.last_reset = datetime.now()
                db.commit()
                logger.info(f"Reset usage for {username}")
            else:
                self.count = 0
                self.last_change_time = datetime.now()
                self._save_state()
                logger.info("Reset usage for anonymous session")
            return self.count
        except Exception as e:
            logger.error(f"Reset usage error for {username or 'anonymous'}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Failed to reset usage: {str(e)}")
    def set_tier(self, tier: str, has_diamond: bool = False, username: str = None, db: Session = None):
        if tier not in level_map:
            raise HTTPException(status_code=400, detail=f"Invalid tier: {tier}. Use 'free', 'beginner', 'pro', or 'diamond'")
        if username and db:
            user = db.query(User).filter(User.username == username).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            if tier == "diamond" and user.tier != "pro":
                raise HTTPException(status_code=400, detail="Diamond add-on requires Pro tier")
            user.tier = tier
            user.has_diamond = has_diamond if tier == "pro" else False
            user.last_reset = datetime.now()
            if tier == "pro" and not user.api_key:
                user.api_key = secrets.token_urlsafe(32)
            if tier == "diamond":
                user.tier = "pro"
                user.has_diamond = True
                user.last_reset = datetime.now() + timedelta(days=30)
            db.commit()
            logger.info(f"Set tier for {username} to {tier}, has_diamond: {user.has_diamond}")
        else:
            self.last_tier = tier
            self.last_change_time = datetime.now()
            os.environ["TIER"] = tier
            self._save_state()
            logger.info(f"Tier switched to: {tier}")
        return f"Switched to {tier} tier" + (f" with Diamond add-on" if has_diamond else "")
    def mock_purchase(self, tier: str, has_diamond: bool = False, username: str = None, db: Session = None):
        if tier in level_map and level_map[tier] > level_map.get(self.last_tier, 0):
            result = self.set_tier(tier, has_diamond, username, db)
            self.count = 0
            return f"Purchase successful. {result}"
        return f"Purchase failed. Cannot downgrade from {self.last_tier} to {tier} or invalid tier."
usage_tracker = UsageTracker()
usage_tracker.set_tier("free")
@retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
def initialize_client():
    logger.info("Starting client initialization...")
    try:
        if not os.getenv("GROK_API_KEY") or not os.getenv("INFURA_PROJECT_ID"):
            logger.error("Missing API keys in .env file")
            raise ValueError("Missing API keys in .env file. Please set GROK_API_KEY and INFURA_PROJECT_ID.")
        client = OpenAI(api_key=os.getenv("GROK_API_KEY"), base_url="https://api.x.ai/v1")
        logger.info("OpenAI client created successfully.")
        infura_url = f"https://mainnet.infura.io/v3/{os.getenv('INFURA_PROJECT_ID')}"
        w3 = Web3(Web3.HTTPProvider(infura_url))
        logger.info("Web3 provider initialized.")
        if not w3.is_connected():
            logger.error("Infura not connected")
            raise ConnectionError("Failed to connect to Ethereum via Infura. Check INFURA_PROJECT_ID.")
        logger.info("Clients initialized successfully.")
        return client, w3
    except Exception as e:
        logger.error(f"Client initialization failed: {str(e)}. Retrying...")
        raise
client, w3 = initialize_client()

## Section 3
def run_echidna(temp_path):
    """Run Echidna fuzzing on the Solidity file and return results."""
    config_path = None
    output_path = None
    try:
        import subprocess
        subprocess.run(["docker", "--version"], check=True, capture_output=True, text=True)
        logger.info("Docker is available, attempting to pull Echidna image")
        @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
        def pull_echidna():
            subprocess.run(["docker", "pull", "trailofbits/echidna"], check=True, capture_output=True, text=True)
            logger.info("Echidna image pulled successfully")
        pull_echidna()
        config_path = os.path.join(DATA_DIR, "echidna_config.yaml")
        output_path = os.path.join(DATA_DIR, "echidna_output")
        with open(config_path, "w") as f:
            f.write("format: text\ntestLimit: 10000\nseqLen: 100\ncoverage: true")
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{DATA_DIR}:/app",
            "trailofbits/echidna",
            f"/app/{os.path.basename(temp_path)}",
            "--config", "/app/echidna_config.yaml",
            "--output", "/app/echidna_output"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                echidna_results = f.read()
        else:
            echidna_results = result.stdout
        logger.info("Echidna fuzzing completed successfully")
        logger.debug(f"Echidna results: {echidna_results}")
        return {"fuzzing_results": echidna_results or "No vulnerabilities found by Echidna"}
    except subprocess.SubprocessError as e:
        logger.error(f"Echidna fuzzing failed: {str(e)}")
        return {"fuzzing_results": "Fuzzing skipped: Docker not available on this environment"}
    except Exception as e:
        logger.error(f"Echidna fuzzing unexpected error: {str(e)}")
        return {"fuzzing_results": f"Fuzzing failed: {str(e)}"}
    finally:
        if config_path and os.path.exists(config_path):
            os.unlink(config_path)
        if output_path and os.path.exists(output_path):
            os.unlink(output_path)
def handle_tool_call(tool_call):
    if tool_call.function.name == "fetch_reg":
        return {"result": "Sample reg data: SEC FIT21 requires custody audits."}
    return {"error": "Unknown tool"}
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "https://defiguard-ai-fresh-private-test.onrender.com"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=secrets.token_urlsafe(32),
    session_cookie="session",
    max_age=3600
)

## Section 4.1: Prompt and Debug Endpoints
PROMPT_TEMPLATE = """
Analyze this Solidity code for vulnerabilities and 2025 regulations (MiCA, SEC FIT21).
Context: {context}.
Fuzzing Results: {fuzzing_results}.
Code: {code}.
Protocol Details: {details}.
Tier: {tier}.
Return the analysis in the exact JSON schema provided. For Beginner/Pro, include detailed predictions and recommendations. For Pro, add advanced regulatory insights and fuzzing results. For Diamond add-on, include formal verification, exploit simulation, threat modeling, fuzzing results, and a remediation roadmap.
"""
# Debug endpoint to test logging
@app.get("/debug")
async def debug_log():
    logger.debug("Debug endpoint called")
    logger.info("Test INFO log")
    logger.warning("Test WARNING log")
    logger.error("Test ERROR log")
    logger.debug("Flushing log file after debug endpoint")
    for handler in logging.getLogger().handlers:
        handler.flush()
    return {"message": "Debug logs written to debug.log and console"}
# Debug static file serving
@app.get("/static/{file_path:path}")
async def serve_static(file_path: str):
    logger.info(f"Serving static file: /static/{file_path}")
    logger.debug("Flushing log file after serving static file")
    for handler in logging.getLogger().handlers:
        handler.flush()
    return StaticFiles(directory="static").get_response(file_path)

## Section 4.2: UI and Auth Endpoints
@app.get("/ui", response_class=HTMLResponse)
async def read_ui(request: Request, session_id: str = Query(None), tier: str = Query(None), has_diamond: bool = Query(False), temp_id: str = Query(None), username: str = Query(None), upgrade: str = Query(None), message: str = Query(None)):
    try:
        session_username = request.session.get("username")
        logger.debug(f"UI request, session_id={session_id}, tier={tier}, has_diamond={has_diamond}, temp_id={temp_id}, username={username}, session_username={session_username}, upgrade={upgrade}, message={message}, session: {request.session}")
        if session_id:
            effective_username = username or session_username
            if not effective_username:
                logger.error("No username provided for post-payment redirect; redirecting to login")
                return RedirectResponse(url="/auth?redirect_reason=no_username")
            if temp_id:
                logger.info(f"Processing post-payment redirect for Diamond audit, username={effective_username}, session_id={session_id}, temp_id={temp_id}")
                return RedirectResponse(url=f"/complete-diamond-audit?session_id={session_id}&temp_id={temp_id}&username={effective_username}")
            if tier:
                logger.info(f"Processing post-payment redirect for tier upgrade, username={effective_username}, session_id={session_id}, tier={tier}, has_diamond={has_diamond}")
                return RedirectResponse(url=f"/complete-tier-checkout?session_id={session_id}&tier={tier}&has_diamond={has_diamond}&username={effective_username}")
        with open("templates/index.html", "r") as f:
            html_content = f.read()
            if upgrade:
                status = "success" if upgrade == "success" else "error"
                message = message or ("Tier upgrade completed" if status == "success" else "Tier upgrade failed")
                html_content = html_content.replace(
                    '<div class="usage-warning" aria-live="assertive">',
                    f'<div class="usage-warning {status}" aria-live="assertive"><p>{message}</p>'
                )
            logger.info(f"Loading UI from: {os.path.abspath('templates/index.html')}")
            logger.debug("Flushing log file after loading UI")
            for handler in logging.getLogger().handlers:
                handler.flush()
            return HTMLResponse(content=html_content)
    except FileNotFoundError:
        logger.error(f"UI file not found: {os.path.abspath('templates/index.html')}")
        return HTMLResponse(content="<h1>UI file not found. Check templates/index.html.</h1>")
@app.get("/auth", response_class=HTMLResponse)
async def read_auth(request: Request):
    try:
        logger.debug(f"Auth page accessed, session: {request.session}")
        # Generate CSRF token for the auth page
        token = await get_csrf_token(request)
        with open("templates/auth.html", "r") as f:
            html_content = f.read()
            # Embed CSRF token in a hidden input for client-side use
            html_content = html_content.replace(
                "</form>",
                f'<input type="hidden" name="csrf_token" value="{token}"></form>'
            )
            logger.info(f"Loading auth from: {os.path.abspath('templates/auth.html')}")
            logger.debug("Flushing log file after loading auth")
            for handler in logging.getLogger().handlers:
                handler.flush()
            return HTMLResponse(content=html_content)
    except FileNotFoundError:
        logger.error(f"Auth file not found: {os.path.abspath('templates/auth.html')}")
        return HTMLResponse(content="<h1>Auth file not found. Check templates folder.</h1>")

## Section 4.3: User and Tier Management Endpoints
from fastapi import Body
from pydantic import BaseModel
import urllib.parse

class TierUpgradeRequest(BaseModel):
    username: Optional[str] = None
    tier: str
    has_diamond: bool = False

@app.post("/signup/{username}")
async def signup(username: str, request: Request, db: Session = Depends(get_db)):
    await verify_csrf_token(request)
    logger.debug(f"Signup request for {username}, session: {request.session}")
    if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
        raise HTTPException(status_code=400, detail="Username must be 3-20 alphanumeric characters or underscores")
    data = await request.json()
    email = data.get("email")
    password = data.get("password")
    csrf_token = data.get("csrf_token")
    if not email or not username or not password or not csrf_token:
        raise HTTPException(status_code=400, detail="Email, username, password, and CSRF token are required")
    if request.session.get("csrf_token") != csrf_token:
        logger.error(f"CSRF validation failed for signup: Provided={csrf_token}, Expected={request.session.get('csrf_token')}")
        raise HTTPException(status_code=403, detail="CSRF token validation failed")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user = User(username=username, email=email, password_hash=password_hash, tier="free", has_diamond=False, last_reset=datetime.now(), api_key=None, audit_history="[]")
    db.add(user)
    db.commit()
    request.session["username"] = username
    logger.info(f"User {username} signed up with free tier, session: {request.session}")
    logger.debug("Flushing log file after signup")
    for handler in logging.getLogger().handlers:
        handler.flush()
    return {"message": f"User {username} signed up with free tier"}

@app.post("/signin/{username}")
async def signin(username: str, request: Request, db: Session = Depends(get_db)):
    await verify_csrf_token(request)
    logger.debug(f"Signin request for {username}, session: {request.session}")
    if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
        raise HTTPException(status_code=400, detail="Invalid username format")
    data = await request.json()
    password = data.get("password")
    csrf_token = data.get("csrf_token")
    if not password or not csrf_token:
        raise HTTPException(status_code=400, detail="Password and CSRF token are required")
    if request.session.get("csrf_token") != csrf_token:
        logger.error(f"CSRF validation failed for signin: Provided={csrf_token}, Expected={request.session.get('csrf_token')}")
        raise HTTPException(status_code=403, detail="CSRF token validation failed")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("utf-8")):
        raise HTTPException(status_code=401, detail="Invalid password")
    request.session["username"] = username
    logger.info(f"User {username} signed in, session: {request.session}")
    logger.debug("Flushing log file after signin")
    for handler in logging.getLogger().handlers:
        handler.flush()
    return {"message": f"Signed in as {username}"}

@app.get("/tier")
async def get_tier(request: Request, username: str = Query(None), db: Session = Depends(get_db)):
    session_username = request.session.get("username")
    logger.debug(f"Tier request: Query username={username}, Session username={session_username}, session: {request.session}")
    if not username and not session_username:
        logger.debug("No username provided for /tier; returning free tier defaults")
        return {
            "tier": "free",
            "size_limit": "1MB",
            "feature_flags": usage_tracker.feature_flags["free"],
            "api_key": None,
            "audit_count": 0,
            "audit_limit": FREE_LIMIT,
            "has_diamond": False
        }
    effective_username = username or session_username
    user = db.query(User).filter(User.username == effective_username).first()
    if not user:
        logger.error(f"Tier fetch failed: User {effective_username} not found")
        raise HTTPException(status_code=404, detail="User not found")
    user_tier = user.tier
    size_limit = "Unlimited" if user.has_diamond else "1MB"
    feature_flags = usage_tracker.feature_flags["diamond" if user.has_diamond else user.tier]
    api_key = user.api_key if user.tier == "pro" else None
    audit_count = usage_tracker.count
    audit_limit = {"free": FREE_LIMIT, "beginner": BEGINNER_LIMIT, "pro": PRO_LIMIT, "diamond": PRO_LIMIT}.get(user.tier, FREE_LIMIT)
    if audit_limit == float("inf"):  # Handle any residual infinite values
        audit_limit = 9999
    has_diamond = user.has_diamond
    logger.debug(f"Retrieved tier for {effective_username}: {user_tier}, audit count: {audit_count}, has_diamond: {has_diamond}")
    logger.debug("Flushing log file after tier retrieval")
    for handler in logging.getLogger().handlers:
        handler.flush()
    return {
        "tier": user_tier,
        "size_limit": size_limit,
        "feature_flags": feature_flags,
        "api_key": api_key,
        "audit_count": audit_count,
        "audit_limit": audit_limit,
        "has_diamond": has_diamond
    }

@app.post("/set-tier/{username}/{tier}")
async def set_tier(username: str, tier: str, has_diamond: bool = Query(False), request: Request = None, db: Session = Depends(get_db)):
    await verify_csrf_token(request)
    logger.debug(f"Set-tier request for {username}, tier: {tier}, has_diamond: {has_diamond}, session: {request.session}")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if tier not in level_map:
        raise HTTPException(status_code=400, detail=f"Invalid tier: {tier}. Use 'free', 'beginner', 'pro', or 'diamond'")
    if tier == "diamond" and user.tier != "pro":
        raise HTTPException(status_code=400, detail="Diamond add-on requires Pro tier")
    if not STRIPE_API_KEY:
        logger.error(f"Stripe checkout creation failed for {username} to {tier}: STRIPE_API_KEY not set")
        raise HTTPException(status_code=503, detail="Payment processing unavailable: Please set STRIPE_API_KEY in environment variables.")
    lock_file = os.path.join(DATA_DIR, "set_tier.lock")
    try:
        with open(lock_file, "w") as f:
            f.write(str(os.getpid()))
        price_id = {"beginner": STRIPE_PRICE_BEGINNER, "pro": STRIPE_PRICE_PRO, "diamond": STRIPE_PRICE_DIAMOND}.get(tier, None)
        if not price_id:
            logger.error(f"Invalid price_id for tier {tier}: price_id={price_id}")
            raise HTTPException(status_code=400, detail="Cannot downgrade or select invalid tier")
        if not all([STRIPE_PRICE_BEGINNER, STRIPE_PRICE_PRO, STRIPE_PRICE_DIAMOND]):
            missing_prices = [var for var in ["STRIPE_PRICE_BEGINNER", "STRIPE_PRICE_PRO", "STRIPE_PRICE_DIAMOND"] if not globals()[var]]
            logger.error(f"Stripe checkout creation failed for {username} to {tier}: Missing Stripe price IDs: {', '.join(missing_prices)}")
            raise HTTPException(status_code=503, detail=f"Payment processing unavailable: Missing Stripe price IDs: {', '.join(missing_prices)}")
        line_items = [{"price": price_id, "quantity": 1}]
        if tier == "pro" and has_diamond:
            line_items.append({"price": STRIPE_PRICE_DIAMOND, "quantity": 1})
        logger.debug(f"Creating Stripe checkout session for {username} to {tier}, line_items={line_items}")
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=line_items,
            mode="subscription",
            success_url=f"https://defiguard-ai-fresh-private.onrender.com/complete-tier-checkout?session_id={{CHECKOUT_SESSION_ID}}&tier={urllib.parse.quote(tier)}&has_diamond={urllib.parse.quote(str(has_diamond).lower())}&username={urllib.parse.quote(username)}",
            cancel_url="https://defiguard-ai-fresh-private.onrender.com/ui",
            metadata={"username": username, "tier": tier, "has_diamond": str(has_diamond).lower()}
        )
        logger.info(f"Redirecting {username} to Stripe checkout for {tier} tier, has_diamond: {has_diamond}, session: {request.session}")
        logger.debug(f"Success URL: {session.url}, params: tier={tier}, has_diamond={has_diamond}, username={username}")
        if session.subscription:
            user.stripe_subscription_id = session.subscription
            for item in stripe.Subscription.retrieve(session.subscription).get("items", {}).get("data", []):
                if item.price.id == STRIPE_METERED_PRICE_DIAMOND:
                    user.stripe_subscription_item_id = item.id
            db.commit()
        return {"session_url": session.url}
    except stripe.error.InvalidRequestError as e:
        logger.error(f"Stripe InvalidRequestError for {username} to {tier}: {str(e)}, error_code={e.code}, param={e.param}")
        raise HTTPException(status_code=400, detail=f"Invalid Stripe request: {e.user_message or str(e)}")
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error for {username} to {tier}: {str(e)}, error_code={e.code}, param={e.param}")
        raise HTTPException(status_code=503, detail=f"Failed to create checkout session: {e.user_message or 'Payment processing error. Please try again or contact support.'}")
    except Exception as e:
        logger.error(f"Unexpected error in Stripe checkout for {username} to {tier}: {str(e)}")
        raise HTTPException(status_code=503, detail=f"Failed to create checkout session: {str(e)}")
    finally:
        if os.path.exists(lock_file):
            os.unlink(lock_file)

@app.post("/create-tier-checkout")
async def create_tier_checkout(tier_request: TierUpgradeRequest = Body(...), request: Request = None, db: Session = Depends(get_db)):
    await verify_csrf_token(request)
    session_username = request.session.get("username")
    logger.debug(f"Create-tier-checkout request with body: {tier_request}, session: {request.session}")
    effective_username = tier_request.username or session_username
    if not effective_username:
        logger.error("No username provided for /create-tier-checkout; redirecting to login")
        raise HTTPException(status_code=401, detail="Please login to continue")
    user = db.query(User).filter(User.username == effective_username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    tier = tier_request.tier
    has_diamond = tier_request.has_diamond
    if tier not in level_map:
        raise HTTPException(status_code=400, detail=f"Invalid tier: {tier}. Use 'free', 'beginner', 'pro', or 'diamond'")
    if tier == "diamond" and user.tier != "pro":
        raise HTTPException(status_code=400, detail="Diamond add-on requires Pro tier")
    if not STRIPE_API_KEY:
        logger.error(f"Stripe checkout creation failed for {effective_username} to {tier}: STRIPE_API_KEY not set")
        raise HTTPException(status_code=503, detail="Payment processing unavailable: Please set STRIPE_API_KEY in environment variables.")
    try:
        price_id = {"beginner": STRIPE_PRICE_BEGINNER, "pro": STRIPE_PRICE_PRO, "diamond": STRIPE_PRICE_DIAMOND}.get(tier, None)
        if not price_id:
            logger.error(f"Invalid price_id for tier {tier}: price_id={price_id}")
            raise HTTPException(status_code=400, detail="Cannot downgrade or select invalid tier")
        if not all([STRIPE_PRICE_BEGINNER, STRIPE_PRICE_PRO, STRIPE_PRICE_DIAMOND]):
            missing_prices = [var for var in ["STRIPE_PRICE_BEGINNER", "STRIPE_PRICE_PRO", "STRIPE_PRICE_DIAMOND"] if not globals()[var]]
            logger.error(f"Stripe checkout creation failed for {effective_username} to {tier}: Missing Stripe price IDs: {', '.join(missing_prices)}")
            raise HTTPException(status_code=503, detail=f"Payment processing unavailable: Missing Stripe price IDs: {', '.join(missing_prices)}")
        line_items = [{"price": price_id, "quantity": 1}]
        if tier == "pro" and has_diamond:
            line_items.append({"price": STRIPE_PRICE_DIAMOND, "quantity": 1})
        logger.debug(f"Creating Stripe checkout session for {effective_username} to {tier}, line_items={line_items}")
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=line_items,
            mode="subscription",
            success_url=f"https://defiguard-ai-fresh-private.onrender.com/complete-tier-checkout?session_id={{CHECKOUT_SESSION_ID}}&tier={urllib.parse.quote(tier)}&has_diamond={urllib.parse.quote(str(has_diamond).lower())}&username={urllib.parse.quote(effective_username)}",
            cancel_url="https://defiguard-ai-fresh-private.onrender.com/ui",
            metadata={"username": effective_username, "tier": tier, "has_diamond": str(has_diamond).lower()}
        )
        logger.info(f"Created Stripe checkout session for {effective_username} to {tier}, has_diamond: {has_diamond}, session: {request.session}")
        logger.debug(f"Success URL: {session.url}, params: tier={tier}, has_diamond={has_diamond}, username={effective_username}")
        if session.subscription:
            user.stripe_subscription_id = session.subscription
            for item in stripe.Subscription.retrieve(session.subscription).get("items", {}).get("data", []):
                if item.price.id == STRIPE_METERED_PRICE_DIAMOND:
                    user.stripe_subscription_item_id = item.id
            db.commit()
        return {"session_url": session.url}
    except stripe.error.InvalidRequestError as e:
        logger.error(f"Stripe InvalidRequestError for {effective_username} to {tier}: {str(e)}, error_code={e.code}, param={e.param}")
        raise HTTPException(status_code=400, detail=f"Invalid Stripe request: {e.user_message or str(e)}")
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error for {effective_username} to {tier}: {str(e)}, error_code={e.code}, param={e.param}")
        raise HTTPException(status_code=503, detail=f"Failed to create checkout session: {e.user_message or 'Payment processing error. Please try again or contact support.'}")
    except Exception as e:
        logger.error(f"Unexpected error in Stripe checkout for {effective_username} to {tier}: {str(e)}")
        raise HTTPException(status_code=503, detail=f"Failed to create checkout session: {str(e)}")

@app.get("/complete-tier-checkout")
async def complete_tier_checkout(session_id: str = Query(...), tier: str = Query(...), has_diamond: bool = Query(False), username: str = Query(...), request: Request = None, db: Session = Depends(get_db)):
    logger.debug(f"Complete-tier-checkout request: session_id={session_id}, tier={tier}, has_diamond={has_diamond}, username={username}, session: {request.session}")
    try:
        # Retrieve the Stripe session
        session = stripe.checkout.Session.retrieve(session_id)
        logger.info(f"Retrieved Stripe session: payment_status={session.payment_status}, session_id={session_id}")

        # Validate payment status
        if session.payment_status == "paid":
            # Update user tier in database
            user = db.query(User).filter(User.username == username).first()
            if not user:
                logger.error(f"User {username} not found for tier upgrade")
                return RedirectResponse(url=f"/ui?upgrade=error&message=User%20not%20found")
            
            user.tier = tier
            user.has_diamond = has_diamond if tier == "pro" else False
            if tier == "pro" and not user.api_key:
                user.api_key = secrets.token_urlsafe(32)
            if tier == "diamond":
                user.tier = "pro"
                user.has_diamond = True
                user.last_reset = datetime.now() + timedelta(days=30)
            if session.subscription:
                user.stripe_subscription_id = session.subscription
                for item in stripe.Subscription.retrieve(session.subscription).get("items", {}).get("data", []):
                    if item.price.id == STRIPE_METERED_PRICE_DIAMOND:
                        user.stripe_subscription_item_id = item.id
                db.commit()
                usage_tracker.set_tier(tier, has_diamond, username, db)
                usage_tracker.reset_usage(username, db)
                request.session["username"] = username  # Ensure session persists
                logger.info(f"Tier upgraded for {username} to {tier}, has_diamond: {has_diamond}, session: {request.session}")
            else:
                logger.warning(f"No subscription found for session {session_id}")

            # Redirect to home page with success message
            return RedirectResponse(url=f"/ui?upgrade=success&message=Tier%20upgrade%20to%20{tier}%20completed")
        else:
            logger.error(f"Payment not completed for {username}, session_id={session_id}, payment_status={session.payment_status}")
            return RedirectResponse(url=f"/ui?upgrade=failed&message=Payment%20failed")
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error during tier checkout for {username}: {str(e)}, error_code={e.code}, param={e.param}")
        return RedirectResponse(url=f"/ui?upgrade=error&message=Payment%20processing%20error:%20{str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error in complete-tier-checkout for {username}: {str(e)}")
        return RedirectResponse(url=f"/ui?upgrade=error&message=Unexpected%20error:%20{str(e)}")
## Section 4.4: Webhook Endpoint
@app.post("/webhook")
async def webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")
    logger.debug(f"Webhook received, payload: {payload[:100]}, sig_header: {sig_header}, session: {request.session}")
    if not STRIPE_API_KEY or not STRIPE_WEBHOOK_SECRET:
        logger.error("Stripe webhook processing failed: STRIPE_API_KEY or STRIPE_WEBHOOK_SECRET not set")
        return Response(status_code=503, content="Webhook processing unavailable: Please set STRIPE_API_KEY and STRIPE_WEBHOOK_SECRET in environment variables.")
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        logger.info(f"Webhook event received: type={event['type']}, id={event['id']}")
    except ValueError as e:
        logger.error(f"Stripe webhook error: Invalid payload - {str(e)}, payload={payload[:200]}")
        return Response(status_code=400, content=f"Invalid payload: {str(e)}")
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Stripe webhook error: Invalid signature - {str(e)}, sig_header={sig_header}")
        return Response(status_code=400, content=f"Invalid signature: {str(e)}")
    except Exception as e:
        logger.error(f"Stripe webhook unexpected error: {str(e)}, payload={payload[:200]}")
        return Response(status_code=500, content=f"Webhook processing failed: {str(e)}")
    try:
        if event["type"] == "checkout.session.completed":
            session = event["data"]["object"]
            username = session["metadata"].get("username")
            temp_id = session["metadata"].get("temp_id")
            tier = session["metadata"].get("tier")
            has_diamond = session["metadata"].get("has_diamond") == "true"
            user = db.query(User).filter(User.username == username).first()
            if user and tier:
                user.stripe_subscription_id = session.subscription
                for item in stripe.Subscription.retrieve(session.subscription).get("items", {}).get("data", []):
                    if item.price.id == STRIPE_METERED_PRICE_DIAMOND:
                        user.stripe_subscription_item_id = item.id
                usage_tracker.set_tier(tier, has_diamond, username, db)
                usage_tracker.reset_usage(username, db)
                request.session["username"] = username # Ensure session persists
                logger.info(f"Tier upgrade completed for {username} to {tier}, has_diamond: {has_diamond}, session: {request.session}")
                db.commit()
            elif temp_id:
                logger.info(f"Payment completed for {username}, starting audit for temp_id {temp_id}, session: {request.session}")
                request.session["username"] = username # Ensure session persists
            else:
                logger.warning(f"Webhook event ignored: missing username or tier/temp_id, event_id={event['id']}")
        else:
            logger.debug(f"Webhook event ignored: unhandled type {event['type']}, event_id={event['id']}")
        return Response(status_code=200)
    except Exception as e:
        logger.error(f"Webhook processing error for event {event['id']}: {str(e)}")
        return Response(status_code=500, content=f"Webhook processing failed: {str(e)}")

## Section 4.5: Audit Endpoints
@app.post("/upload-temp")
async def upload_temp(file: UploadFile = File(...), username: str = Query(None), db: Session = Depends(get_db), request: Request = None):
    await verify_csrf_token(request)
    session_username = request.session.get("username")
    logger.debug(f"Upload-temp request: Query username={username}, Session username={session_username}, session: {request.session}")
    effective_username = username or session_username
    if not effective_username:
        logger.error("No username provided for /upload-temp; redirecting to login")
        raise HTTPException(status_code=401, detail="Please login to continue")
    user = db.query(User).filter(User.username == effective_username).first()
    if not user or not user.has_diamond:
        raise HTTPException(status_code=403, detail="Temporary file upload requires Diamond add-on")
    temp_id = str(uuid.uuid4())
    temp_dir = os.path.join(DATA_DIR, "temp_files")
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, f"{temp_id}.sol")
    try:
        code_bytes = await file.read()
        file_size = len(code_bytes)
        with open(temp_path, "wb") as f:
            f.write(code_bytes)
    except PermissionError as e:
        logger.error(f"Failed to write temp file: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to save temporary file due to permissions")
    except Exception as e:
        logger.error(f"Upload temp file failed for {effective_username}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to upload temporary file: {str(e)}")
    logger.info(f"Temporary file uploaded for {effective_username}: {temp_id}, size: {file_size / 1024 / 1024:.2f}MB")
    return {"temp_id": temp_id, "file_size": file_size}

@app.post("/diamond-audit")
async def diamond_audit(file: UploadFile = File(...), username: str = Query(None), db: Session = Depends(get_db), request: Request = None):
    await verify_csrf_token(request)
    session_username = request.session.get("username")
    logger.debug(f"Diamond-audit request: Query username={username}, Session username={session_username}, session: {request.session}")
    effective_username = username or session_username
    if not effective_username:
        logger.error("No username provided for /diamond-audit; redirecting to login")
        raise HTTPException(status_code=401, detail="Please login to continue")
    user = db.query(User).filter(User.username == effective_username).first()
    if not user or not user.has_diamond:
        raise HTTPException(status_code=403, detail="Diamond audit requires Diamond add-on")
    try:
        code_bytes = await file.read()
        file_size = len(code_bytes)
        if file_size > 50 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File size exceeds 50MB limit")
        overage_cost = usage_tracker.calculate_diamond_overage(file_size)
        logger.info(f"Preparing Diamond audit for {effective_username} with overage ${overage_cost / 100:.2f} for file size {file_size / 1024 / 1024:.2f}MB")
        temp_id = str(uuid.uuid4())
        temp_dir = os.path.join(DATA_DIR, "temp_files")
        os.makedirs(temp_dir, exist_ok=True)
        temp_path = os.path.join(temp_dir, f"{temp_id}.sol")
        try:
            with open(temp_path, "wb") as f:
                f.write(code_bytes)
        except PermissionError as e:
            logger.error(f"Failed to write temp file: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to save temporary file due to permissions")
        if not STRIPE_API_KEY:
            logger.error(f"Stripe checkout creation failed for {effective_username} Diamond audit: STRIPE_API_KEY not set")
            os.unlink(temp_path)
            raise HTTPException(status_code=503, detail="Payment processing unavailable: Please set STRIPE_API_KEY in environment variables.")
        if not STRIPE_METERED_PRICE_DIAMOND:
            logger.error(f"Stripe checkout creation failed for {effective_username} Diamond audit: STRIPE_METERED_PRICE_DIAMOND not set")
            os.unlink(temp_path)
            raise HTTPException(status_code=503, detail="Payment processing unavailable: Missing STRIPE_METERED_PRICE_DIAMOND in environment variables.")
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{"price": STRIPE_METERED_PRICE_DIAMOND, "quantity": 1}],
            mode="subscription",
            success_url=f"https://defiguard-ai-fresh-private-test.onrender.com/complete-diamond-audit?session_id={{CHECKOUT_SESSION_ID}}&temp_id={urllib.parse.quote(temp_id)}&username={urllib.parse.quote(effective_username)}",
            cancel_url="https://defiguard-ai-fresh-private-test.onrender.com/ui",
            metadata={"temp_id": temp_id, "username": effective_username}
        )
        logger.info(f"Redirecting {effective_username} to Stripe checkout for Diamond audit overage, session: {request.session}")
        return {"session_url": session.url}
    except Exception as e:
        logger.error(f"Diamond audit error for {effective_username}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

@app.get("/complete-diamond-audit")
async def complete_diamond_audit(session_id: str = Query(...), temp_id: str = Query(...), username: str = Query(None), request: Request = None, db: Session = Depends(get_db)):
    session_username = request.session.get("username")
    logger.debug(f"Complete-diamond-audit request: Query username={username}, Session username={session_username}, session_id={session_id}, temp_id={temp_id}, session: {request.session}")
    effective_username = username or session_username
    if not effective_username:
        logger.error("No username provided for /complete-diamond-audit; redirecting to login")
        return RedirectResponse(url="/auth?redirect_reason=no_username")
    user = db.query(User).filter(User.username == effective_username).first()
    if not user:
        logger.error(f"User {effective_username} not found for /complete-diamond-audit")
        return RedirectResponse(url="/auth?redirect_reason=user_not_found")
    if not STRIPE_API_KEY:
        logger.error(f"Complete diamond audit failed for {effective_username}: STRIPE_API_KEY not set")
        return RedirectResponse(url="/ui?upgrade=error&message=Payment%20processing%20unavailable")
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.payment_status == "paid":
            temp_path = os.path.join(DATA_DIR, "temp_files", f"{temp_id}.sol")
            if not os.path.exists(temp_path):
                raise HTTPException(status_code=404, detail="Temporary file not found")
            with open(temp_path, "rb") as f:
                file = UploadFile(filename="temp.sol", file=f)
                result = await audit_contract(file, None, effective_username, db, request)
            os.unlink(temp_path)
            logger.info(f"Diamond audit completed for {effective_username} after payment, session: {request.session}")
            return RedirectResponse(url="/ui?upgrade=success")
        else:
            logger.error(f"Payment not completed for {effective_username}, session_id={session_id}, payment_status={session.payment_status}")
            return RedirectResponse(url="/ui?upgrade=failed")
    except Exception as e:
        logger.error(f"Complete diamond audit failed for {effective_username}: {str(e)}")
        return RedirectResponse(url=f"/ui?upgrade=error&message={str(e)}")

@app.get("/api/audit")
async def api_audit(username: str, api_key: str, db: Session = Depends(get_db)):
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or user.api_key != api_key or user.tier != "pro":
            raise HTTPException(status_code=403, detail="API access requires Pro tier and valid API key")
        logger.info(f"API audit endpoint accessed by {username}")
        return {"message": "API audit endpoint (Pro tier)"}
    except Exception as e:
        logger.error(f"API audit error for {username}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

@app.get("/upgrade")
async def upgrade_page():
    try:
        logger.debug("Upgrade page accessed")
        return {"message": "Upgrade at /ui for Beginner ($50/mo), Pro ($200/mo), or Diamond add-on ($50/mo with Pro)."}
    except Exception as e:
        logger.error(f"Upgrade page error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

@app.get("/facets/{contract_address}")
async def get_facets(contract_address: str, request: Request, username: str = Query(None), db: Session = Depends(get_db)):
    try:
        logger.debug(f"Received /facets request for {contract_address} by {username or 'anonymous'}, session: {request.session}")
        if not w3.is_address(contract_address):
            logger.error(f"Invalid Ethereum address: {contract_address}")
            raise HTTPException(status_code=400, detail="Invalid Ethereum address")
        session_username = request.session.get("username")
        effective_username = username or session_username
        user = db.query(User).filter(User.username == effective_username).first() if effective_username else None
        current_tier = user.tier if user else os.getenv("TIER", "free")
        has_diamond = user.has_diamond if user else False
        if current_tier not in ["pro", "diamond"] and not has_diamond:
            logger.warning(f"Facet preview denied for {effective_username or 'anonymous'} (tier: {current_tier}, has_diamond: {has_diamond})")
            raise HTTPException(status_code=403, detail="Facet preview requires Pro tier or Diamond add-on. Upgrade at /ui.")
        if not INFURA_PROJECT_ID:
            logger.error(f"Facet fetch failed for {effective_username}: INFURA_PROJECT_ID not set")
            raise HTTPException(status_code=503, detail="On-chain analysis unavailable: Please set INFURA_PROJECT_ID in environment variables.")
        diamond_abi = [
            {
                "inputs": [{"internalType": "bytes4", "name": "_functionSelector", "type": "bytes4"}],
                "name": "facetAddress",
                "outputs": [{"internalType": "address", "name": "", "type": "address"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [],
                "name": "facets",
                "outputs": [
                    {
                        "components": [
                            {"internalType": "address", "name": "facetAddress", "type": "address"},
                            {"internalType": "bytes4[]", "name": "functionSelectors", "type": "bytes4[]"}
                        ],
                        "internalType": "struct IDiamondLoupe.Facet[]",
                        "name": "",
                        "type": "tuple[]"
                    }
                ],
                "stateMutability": "view",
                "type": "function"
            }
        ]
        contract = w3.eth.contract(address=contract_address, abi=diamond_abi)
        facets = contract.functions.facets().call()
        facet_data = [
            {
                "facetAddress": facet[0],
                "functionSelectors": [selector.hex() for selector in facet[1]][:2] if current_tier == "pro" and not has_diamond else [selector.hex() for selector in facet[1]],
                "functions": [selector[:10] for selector in facet[1]][:2] if current_tier == "pro" and not has_diamond else [selector[:10] for selector in facet[1]]
            }
            for facet in facets
        ]
        logger.info(f"Retrieved {len(facet_data)} facets for {contract_address}")
        return {"facets": facet_data, "is_preview": current_tier == "pro" and not has_diamond}
    except Exception as e:
        logger.error(f"Facet endpoint error for {username or 'anonymous'}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
## Section 4.6: Main Audit Endpoint
@app.post("/audit", response_model=AuditResponse)
async def audit_contract(file: UploadFile = File(...), contract_address: str = None, username: str = Query(None), db: Session = Depends(get_db), request: Request = None):
    await verify_csrf_token(request)
    session_username = request.session.get("username")
    logger.debug(f"Audit request: Query username={username}, Session username={session_username}, session: {request.session}")
    effective_username = username or session_username
    if not effective_username:
        logger.error("No username provided for /audit; redirecting to login")
        raise HTTPException(status_code=401, detail="Please login to continue")
    user = db.query(User).filter(User.username == effective_username).first()
    if not user:
        logger.error(f"Audit failed: User {effective_username} not found")
        raise HTTPException(status_code=401, detail="Please login to continue")
    raw_response = None
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    code_bytes = None
    file_size = 0
    temp_path = None
    context = ""
    fuzzing_results = []
    # File reading block with size pre-check
    try:
        if file.size > 100 * 1024 * 1024:  # 100MB limit
            logger.error(f"File size {file.size / 1024 / 1024:.2f}MB exceeds 100MB limit for {effective_username}")
            raise HTTPException(status_code=400, detail="File exceeds 100MB limit")
        logger.debug(f"Reading file for {effective_username}")
        code_bytes = await file.read()
        file_size = len(code_bytes)
        logger.info(f"File read successfully: {file_size} bytes for user {effective_username}")
    except Exception as e:
        logger.error(f"File read failed for {effective_username}: {str(e)}")
        raise HTTPException(status_code=400, detail=f"File read failed: {str(e)}")
    # Validate file size and tier with broader exception handling
    try:
        current_tier = user.tier
        overage_cost = None
        if file_size > 1024 * 1024 and not user.has_diamond:
            overage_cost = usage_tracker.calculate_diamond_overage(file_size) / 100
            logger.warning(f"File size {file_size / 1024 / 1024:.2f}MB exceeds limit for {effective_username} (tier: {current_tier})")
            raise HTTPException(
                status_code=400,
                detail=f"Access to Diamond audits is only available on Pro tier with Diamond add-on. Upgrade to Pro + Diamond ($200/mo + $50/mo + ${overage_cost:.2f} overage for this file)."
            )
        limits = {"free": FREE_LIMIT, "beginner": BEGINNER_LIMIT, "pro": PRO_LIMIT, "diamond": PRO_LIMIT}
        try:
            current_count = usage_tracker.increment(file_size, effective_username, db)
            logger.info(f"Audit request {current_count} processed for contract {contract_address or 'uploaded'} with tier {current_tier} for user {effective_username}")
        except Exception as e:
            if isinstance(e, HTTPException) and e.status_code == 400 and "exceeds" in e.detail:
                logger.info(f"File size exceeds limit for {effective_username}; redirecting to upgrade")
                temp_id = str(uuid.uuid4())
                temp_dir = os.path.join(DATA_DIR, "temp_files")
                os.makedirs(temp_dir, exist_ok=True)
                temp_path = os.path.join(temp_dir, f"{temp_id}.sol")
                try:
                    with open(temp_path, "wb") as f:
                        f.write(code_bytes)
                    logger.debug(f"Temporary file saved: {temp_path} for {effective_username}")
                except PermissionError as e:
                    logger.error(f"Failed to write temp file: {str(e)}")
                    raise HTTPException(status_code=500, detail="Failed to save temporary file due to permissions")
                if not STRIPE_API_KEY:
                    logger.error(f"Stripe checkout creation failed for {effective_username} Pro upgrade: STRIPE_API_KEY not set")
                    os.unlink(temp_path)
                    raise HTTPException(status_code=503, detail="Payment processing unavailable: Please set STRIPE_API_KEY in environment variables.")
                if not all([STRIPE_PRICE_PRO, STRIPE_PRICE_DIAMOND]):
                    missing_prices = [var for var in ["STRIPE_PRICE_PRO", "STRIPE_PRICE_DIAMOND"] if not globals()[var]]
                    logger.error(f"Stripe checkout creation failed for {effective_username} Pro upgrade: Missing Stripe price IDs: {', '.join(missing_prices)}")
                    os.unlink(temp_path)
                    raise HTTPException(status_code=503, detail=f"Payment processing unavailable: Missing Stripe price IDs: {', '.join(missing_prices)}")
                try:
                    session = stripe.checkout.Session.create(
                        payment_method_types=["card"],
                        line_items=[{"price": STRIPE_PRICE_PRO, "quantity": 1}, {"price": STRIPE_PRICE_DIAMOND, "quantity": 1}],
                        mode="subscription",
                        success_url=f"https://defiguard-ai-fresh-private.onrender.com/ui?session_id={{CHECKOUT_SESSION_ID}}&tier=pro&has_diamond=true",
                        cancel_url="https://defiguard-ai-fresh-private.onrender.com/ui",
                        metadata={"username": effective_username, "tier": "pro", "has_diamond": "true"}
                    )
                    logger.info(f"Redirecting {effective_username} to Stripe checkout for Pro tier with Diamond add-on due to file size")
                    return {"session_url": session.url}
                except stripe.error.InvalidRequestError as e:
                    logger.error(f"Stripe InvalidRequestError for {effective_username} Pro upgrade: {str(e)}, error_code={e.code}, param={e.param}")
                    os.unlink(temp_path)
                    raise HTTPException(status_code=400, detail=f"Invalid Stripe request: {e.user_message or str(e)}")
                except stripe.error.StripeError as e:
                    logger.error(f"Stripe error for {effective_username} Pro upgrade: {str(e)}, error_code={e.code}, param={e.param}")
                    os.unlink(temp_path)
                    raise HTTPException(status_code=503, detail=f"Failed to create checkout session: {e.user_message or 'Payment processing error. Please try again or contact support.'}")
                except Exception as e:
                    logger.error(f"Unexpected error in Stripe checkout for {effective_username} Pro upgrade: {str(e)}")
                    os.unlink(temp_path)
                    raise HTTPException(status_code=503, detail=f"Failed to create checkout session: {str(e)}")
            elif isinstance(e, HTTPException) and e.status_code == 403 and "Usage limit exceeded" in e.detail:
                logger.info(f"Usage limit exceeded for {effective_username}; redirecting to upgrade")
                if not STRIPE_API_KEY:
                    logger.error(f"Stripe checkout creation failed for {effective_username} Beginner upgrade: STRIPE_API_KEY not set")
                    raise HTTPException(status_code=503, detail="Payment processing unavailable: Please set STRIPE_API_KEY in environment variables.")
                if not STRIPE_PRICE_BEGINNER:
                    logger.error(f"Stripe checkout creation failed for {effective_username} Beginner upgrade: STRIPE_PRICE_BEGINNER not set")
                    raise HTTPException(status_code=503, detail="Payment processing unavailable: Missing STRIPE_PRICE_BEGINNER in environment variables.")
                try:
                    session = stripe.checkout.Session.create(
                        payment_method_types=["card"],
                        line_items=[{"price": STRIPE_PRICE_BEGINNER, "quantity": 1}],
                        mode="subscription",
                        success_url=f"https://defiguard-ai-fresh-private.onrender.com/ui?session_id={{CHECKOUT_SESSION_ID}}&tier=beginner",
                        cancel_url="https://defiguard-ai-fresh-private.onrender.com/ui",
                        metadata={"username": effective_username, "tier": "beginner"}
                    )
                    logger.info(f"Redirecting {effective_username} to Stripe checkout for Beginner tier due to usage limit")
                    return {"session_url": session.url}
                except stripe.error.InvalidRequestError as e:
                    logger.error(f"Stripe InvalidRequestError for {effective_username} Beginner upgrade: {str(e)}, error_code={e.code}, param={e.param}")
                    raise HTTPException(status_code=400, detail=f"Invalid Stripe request: {e.user_message or str(e)}")
                except stripe.error.StripeError as e:
                    logger.error(f"Stripe error for {effective_username} Beginner upgrade: {str(e)}, error_code={e.code}, param={e.param}")
                    raise HTTPException(status_code=503, detail=f"Failed to create checkout session: {e.user_message or 'Payment processing error. Please try again or contact support.'}")
                except Exception as e:
                    logger.error(f"Unexpected error in Stripe checkout for {effective_username} Beginner upgrade: {str(e)}")
                    raise HTTPException(status_code=503, detail=f"Failed to create checkout session: {str(e)}")
            else:
                raise e
    except Exception as e:
        logger.error(f"Tier or usage check error for {effective_username}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Tier or usage check failed: {str(e)}")

    # Audit processing block with transaction
    try:
        logger.info(f"Starting audit process for {effective_username}")
        try:
            code_str = code_bytes.decode("utf-8")
            logger.debug(f"File decoded successfully for {effective_username}")
        except UnicodeDecodeError as decode_err:
            logger.error(f"File decoding failed for {effective_username}: {str(decode_err)}")
            raise HTTPException(status_code=400, detail=f"File decoding failed: {str(decode_err)}")
        if not code_str.strip():
            logger.error(f"Empty file uploaded for {effective_username}")
            raise HTTPException(status_code=400, detail="Empty file uploaded.")
        temp_dir = os.path.join(DATA_DIR, "temp_files")
        os.makedirs(temp_dir, exist_ok=True)
        with NamedTemporaryFile(delete=False, suffix=".sol", dir=temp_dir) as temp_file:
            temp_file.write(code_bytes)
            temp_path = temp_file.name
            if platform.system() == "Windows":
                temp_path = temp_path.replace("/", "\\")
        logger.debug(f"Temporary file created for {effective_username}: {temp_path}")

        # Slither analysis with API validation
        try:
            logger.info(f"Starting Slither analysis for {effective_username}")
            @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
            def analyze_slither(temp_path, chunk_size=500000, attempt_number=1):
                logger.debug(f"Slither retry attempt {attempt_number} for {effective_username}")
                try:
                    with open(temp_path, "r", encoding="utf-8") as f:
                        code = f.read()
                        if len(code) > chunk_size:
                            chunks = [code[i:i + chunk_size] for i in range(0, len(code), chunk_size)]
                            findings = []
                            for i, chunk in enumerate(chunks):
                                chunk_file_path = os.path.join(temp_dir, f"chunk_{i}.sol")
                                with open(chunk_file_path, "wb") as chunk_file:
                                    chunk_file.write(chunk.encode("utf-8"))
                                slither = Slither(chunk_file_path)
                                if not hasattr(slither, 'detectors'):
                                    raise HTTPException(status_code=500, detail="Slither API mismatch")
                                for contract in slither.contracts:
                                    findings.extend(detector.detect() for detector in slither.detectors)
                                os.unlink(chunk_file_path)
                            return findings
                        else:
                            slither = Slither(temp_path)
                            if not hasattr(slither, 'detectors'):
                                raise HTTPException(status_code=500, detail="Slither API mismatch")
                            return [finding for contract in slither.contracts for detector in slither.detectors for finding in detector.detect()]
                except SlitherError as e:
                    logger.error(f"Slither analysis failed on attempt {attempt_number}: {str(e)}")
                    if attempt_number < 3:
                        raise
                    raise HTTPException(status_code=400, detail=f"Slither analysis failed: {str(e)}")
                except Exception as e:
                    logger.error(f"Unexpected Slither error on attempt {attempt_number}: {str(e)}")
                    raise HTTPException(status_code=500, detail=f"Unexpected Slither error: {str(e)}")
            findings = analyze_slither(temp_path)
            context = json.dumps([finding.to_json() for finding in findings]).replace('"', '\"') if findings else "No static issues found"
            logger.debug(f"Slither findings for {effective_username}: {context[:200]}")
        except HTTPException as e:
            raise e
        except Exception as e:
            logger.error(f"Slither processing failed for {effective_username}: {str(e)}")
            context = f"Slither analysis failed: {str(e)}; proceeding with raw code"

        # Echidna fuzzing with configurable timeout
        ECHIDNA_TIMEOUT = 600  # Configurable timeout in seconds
        if usage_tracker.feature_flags["diamond" if user.has_diamond else current_tier]["fuzzing"]:
            logger.info(f"Starting Echidna fuzzing for {effective_username}")
            try:
                @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
                def run_echidna(temp_path, attempt_number=1):
                    logger.debug(f"Echidna retry attempt {attempt_number} for {effective_username}")
                    try:
                        import subprocess
                        subprocess.run(["docker", "--version"], check=True, capture_output=True, text=True)
                        if os.path.getsize(temp_path) > 20 * 1024 * 1024:  # Increased to 20MB for Diamond
                            logger.warning(f"File size {os.path.getsize(temp_path) / 1024 / 1024:.2f}MB exceeds Echidna limit, skipping")
                            return {"fuzzing_results": "Fuzzing skipped: File size exceeds 20MB limit"}
                        config_path = os.path.join(DATA_DIR, "echidna_config.yaml")
                        output_path = os.path.join(DATA_DIR, "echidna_output")
                        with open(config_path, "w") as f:
                            f.write("format: text\ntestLimit: 10000\nseqLen: 100\ncoverage: true")
                        cmd = [
                            "docker", "run", "--rm",
                            "-v", f"{DATA_DIR}:/app",
                            "trailofbits/echidna",
                            f"/app/{os.path.basename(temp_path)}",
                            "--config", "/app/echidna_config.yaml",
                            "--output", "/app/echidna_output"
                        ]
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=ECHIDNA_TIMEOUT)
                        if os.path.exists(output_path):
                            with open(output_path, "r") as f:
                                return {"fuzzing_results": f.read()}
                        return {"fuzzing_results": result.stdout or "No vulnerabilities found by Echidna"}
                    except subprocess.SubprocessError as e:
                        logger.error(f"Echidna subprocess failed on attempt {attempt_number}: {str(e)}")
                        if attempt_number < 3:
                            raise
                        return {"fuzzing_results": f"Fuzzing failed: {str(e)}"}
                    except Exception as e:
                        logger.error(f"Unexpected Echidna error on attempt {attempt_number}: {str(e)}")
                        if attempt_number < 3:
                            raise
                        return {"fuzzing_results": f"Fuzzing failed: {str(e)}"}
                    finally:
                        if os.path.exists(config_path):
                            os.unlink(config_path)
                        if os.path.exists(output_path):
                            os.unlink(output_path)
                echidna_output = run_echidna(temp_path)
                if isinstance(echidna_output["fuzzing_results"], str):
                    fuzzing_results = [{"vulnerability": "Potential issue", "description": echidna_output["fuzzing_results"]}]
                else:
                    fuzzing_results = echidna_output["fuzzing_results"]
                context += f"\nEchidna fuzzing results: {json.dumps(fuzzing_results)}"
                logger.debug(f"Echidna fuzzing results for {effective_username}: {json.dumps(fuzzing_results)[:200]}")
            except Exception as e:
                logger.error(f"Echidna processing failed for {effective_username}: {str(e)}")
                fuzzing_results = [{"vulnerability": "Fuzzing unavailable", "description": str(e)}]
        else:
            logger.info(f"Fuzzing skipped for {current_tier} tier for {effective_username}")

        # On-chain analysis if enabled
        if contract_address and not usage_tracker.feature_flags["diamond" if user.has_diamond else current_tier]["onchain"]:
            logger.warning(f"On-chain analysis denied for {effective_username} (tier: {current_tier}, has_diamond: {user.has_diamond})")
            raise HTTPException(status_code=403, detail="On-chain analysis requires Beginner tier or higher.")
        details = "Uploaded Solidity code for analysis."
        if contract_address:
            if not INFURA_PROJECT_ID:
                logger.error(f"On-chain analysis failed for {effective_username}: INFURA_PROJECT_ID not set")
                raise HTTPException(status_code=503, detail="On-chain analysis unavailable: Please set INFURA_PROJECT_ID in environment variables.")
            if not w3.is_address(contract_address):
                logger.error(f"Invalid Ethereum address for {effective_username}: {contract_address}")
                raise HTTPException(status_code=400, detail="Invalid Ethereum address.")
            try:
                onchain_code = w3.eth.get_code(contract_address)
                details += f" On-chain code fetched for {contract_address} (bytecode length: {len(onchain_code)})."
                logger.debug(f"On-chain code fetched for {effective_username}: {contract_address}, length: {len(onchain_code)}")
            except Exception as e:
                logger.error(f"On-chain code fetch failed for {effective_username}: {str(e)}")
                details += f" No deployed code found at {contract_address}."

        # Grok API processing with transaction and JSON validation
        if user.has_diamond and file_size > 1024 * 1024:
            chunks = [code_str[i:i + 500000] for i in range(0, len(code_str), 500000)]
            results = []
            if not os.getenv("GROK_API_KEY"):
                logger.error(f"Grok API call failed for {effective_username}: GROK_API_KEY not set")
                raise HTTPException(status_code=503, detail="Audit processing unavailable: Please set GROK_API_KEY in environment variables.")
            for i, chunk in enumerate(chunks):
                logger.info(f"Processing chunk {i+1}/{len(chunks)} for {effective_username}")
                prompt = PROMPT_TEMPLATE.format(context=context, fuzzing_results=json.dumps(fuzzing_results), code=chunk, details=details, tier="diamond")
                try:
                    response = client.chat.completions.create(
                        model="grok-4",
                        messages=[{"role": "user", "content": prompt}],
                        temperature=0.0,
                        response_format={
                            "type": "json_schema",
                            "json_schema": {"schema": AUDIT_SCHEMA},
                            "strict": True
                        }
                    )
                    if response.choices and response.choices[0].message.content:
                        try:
                            results.append(json.loads(response.choices[0].message.content))
                        except json.JSONDecodeError as e:
                            logger.error(f"Invalid Grok response format for chunk {i+1} for {effective_username}: {str(e)}")
                            raise HTTPException(status_code=500, detail=f"Invalid Grok response format: {str(e)}")
                        logger.debug(f"Grok API response for chunk {i+1} for {effective_username}: {response.choices[0].message.content[:200]}")
                    else:
                        logger.error(f"No Grok API response for chunk {i+1} for {effective_username}")
                        raise HTTPException(status_code=500, detail=f"No response from Grok API for chunk {i+1}")
                except Exception as e:
                    logger.error(f"Grok API call failed for {effective_username}, chunk {i+1}: {str(e)}")
                    raise HTTPException(status_code=500, detail=f"Grok API call failed for chunk {i+1}: {str(e)}")
            with db.begin():  # Transaction for database updates
                aggregated = {
                    "risk_score": max(r["risk_score"] for r in results),
                    "issues": sum([r["issues"] for r in results], []),
                    "predictions": sum([r["predictions"] for r in results], []),
                    "recommendations": sum([r["recommendations"] for r in results], []),
                    "remediation_roadmap": "Detailed plan: Prioritize high-severity issues, implement fixes, and schedule manual review.",
                    "fuzzing_results": fuzzing_results
                }
                user = db.query(User).filter(User.username == effective_username).first()
                if user:
                    history = json.loads(user.audit_history)
                    history.append({"contract": contract_address or "uploaded", "timestamp": datetime.now().isoformat(), "risk_score": aggregated["risk_score"]})
                    user.audit_history = json.dumps(history)
                    overage_mb = (file_size - 1024 * 1024) / (1024 * 1024)
                    if overage_mb > 0 and user.stripe_subscription_id and user.stripe_subscription_item_id:
                        try:
                            stripe.SubscriptionItem.create_usage_record(
                                user.stripe_subscription_item_id,
                                quantity=int(overage_mb),
                                timestamp=int(time.time()),
                                action="increment"
                            )
                            logger.info(f"Reported {overage_mb:.2f}MB overage for {effective_username} to Stripe")
                        except Exception as e:
                            logger.error(f"Failed to report overage for {effective_username}: {str(e)}")
                        db.commit()  # Commit within transaction if overage succeeds
            return {"report": aggregated, "risk_score": str(aggregated["risk_score"]), "overage_cost": overage_cost}
        else:
            logger.info(f"Calling Grok API for {effective_username} with tier {current_tier}")
            if not os.getenv("GROK_API_KEY"):
                logger.error(f"Grok API call failed for {effective_username}: GROK_API_KEY not set")
                raise HTTPException(status_code=503, detail="Audit processing unavailable: Please set GROK_API_KEY in environment variables.")
            prompt = PROMPT_TEMPLATE.format(context=context, fuzzing_results=json.dumps(fuzzing_results), code=code_str, details=details, tier="diamond" if user.has_diamond else current_tier)
            try:
                response = client.chat.completions.create(
                    model="grok-4",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.0,
                    response_format={
                        "type": "json_schema",
                        "json_schema": {"schema": AUDIT_SCHEMA},
                        "strict": True
                    }
                )
                logger.info(f"Grok API response received for {effective_username}")
                if response.choices and response.choices[0].message.content:
                    raw_response = response.choices[0].message.content
                    logger.debug(f"Raw Grok Response for {effective_username}: {raw_response[:200]}")
                    with open(os.path.join(DATA_DIR, "debug.log"), "a") as f:
                        f.write(f"[{timestamp}] DEBUG: Raw Grok Response: {raw_response}\n")
                        f.flush()
                    try:
                        audit_json = json.loads(raw_response)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid Grok response format for {effective_username}: {str(e)}")
                        raise HTTPException(status_code=500, detail=f"Invalid Grok response format: {str(e)}")
                    if user.has_diamond:
                        audit_json["remediation_roadmap"] = "Detailed plan: Prioritize high-severity issues, implement fixes, and schedule manual review."
                    audit_json["fuzzing_results"] = fuzzing_results
                    with db.begin():  # Transaction for database updates
                        user = db.query(User).filter(User.username == effective_username).first()
                        if user:
                            history = json.loads(user.audit_history)
                            history.append({"contract": contract_address or "uploaded", "timestamp": datetime.now().isoformat(), "risk_score": audit_json["risk_score"]})
                            user.audit_history = json.dumps(history)
                            overage_mb = (file_size - 1024 * 1024) / (1024 * 1024)
                            if overage_mb > 0 and user.stripe_subscription_id and user.stripe_subscription_item_id:
                                try:
                                    stripe.SubscriptionItem.create_usage_record(
                                        user.stripe_subscription_item_id,
                                        quantity=int(overage_mb),
                                        timestamp=int(time.time()),
                                        action="increment"
                                    )
                                    logger.info(f"Reported {overage_mb:.2f}MB overage for {effective_username} to Stripe")
                                except Exception as e:
                                    logger.error(f"Failed to report overage for {effective_username}: {str(e)}")
                                db.commit()  # Commit within transaction if overage succeeds
                    return {"report": audit_json, "risk_score": str(audit_json.get("risk_score", "N/A")), "overage_cost": overage_cost}
                else:
                    logger.error(f"No Grok API response for {effective_username}")
                    raise HTTPException(status_code=500, detail="No response from Grok API")
            except Exception as e:
                logger.error(f"Grok API call failed for {effective_username}: {str(e)}")
                raise HTTPException(status_code=500, detail=f"Grok API call failed: {str(e)}")
    except Exception as e:
        logger.error(f"Audit processing error for {effective_username}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Audit processing failed: {str(e)}")
    finally:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
            logger.debug(f"Temporary file deleted: {temp_path} for {effective_username}")

## Section 4.6: Main Entry Point
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
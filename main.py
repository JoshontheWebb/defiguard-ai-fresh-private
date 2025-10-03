# === IMPORTS ===
import os
import json
import logging
import bcrypt
import sqlite3
import subprocess
from typing import Optional
from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Depends, Query, Response
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from openai import OpenAI
from slither.slither import Slither
from slither.exceptions import SlitherError
from web3 import Web3
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from tempfile import NamedTemporaryFile
import re
import platform
import sys
from datetime import datetime, timedelta
import time
from tenacity import retry, stop_after_attempt, wait_fixed
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
import secrets
from starlette.middleware.sessions import SessionMiddleware
import stripe
import uuid

# === ENVIRONMENT AND LOGGING ===
load_dotenv()
GROK_API_KEY = os.getenv("GROK_API_KEY")
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")
STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

if not GROK_API_KEY or not INFURA_PROJECT_ID or not STRIPE_API_KEY:
    raise ValueError("Missing API keys in .env file. Please set GROK_API_KEY, INFURA_PROJECT_ID, and STRIPE_API_KEY.")

try:
    with open('debug.log', 'a') as f:
        f.write("Logging initialized at " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n")
        f.flush()
except Exception as e:
    print(f"Error initializing log file: {e}", file=sys.stderr)
logging.basicConfig(
    level=logging.DEBUG,
    filename='debug.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    force=True
)
logger = logging.getLogger(__name__)
handler = logging.getLogger().handlers[0]
handler.flush = lambda: handler.stream.flush()

# === DATABASE SETUP ===
Base = declarative_base()
engine = create_engine("sqlite:///users.db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String)
    password_hash = Column(String)
    tier = Column(String, default="free")
    last_reset = Column(DateTime, default=datetime.now)
    api_key = Column(String, nullable=True)
    audit_history = Column(String, default="[]")

# Migrate database schema
def migrate_database():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(users)")
    columns = [info[1] for info in cursor.fetchall()]
    if 'api_key' not in columns or 'audit_history' not in columns:
        logger.info("Migrating users table to add api_key and audit_history columns")
        cursor.execute("SELECT id, username, email, password_hash, tier, last_reset FROM users")
        old_data = cursor.fetchall()
        cursor.execute("DROP TABLE IF EXISTS users")
        Base.metadata.create_all(bind=engine)
        for row in old_data:
            cursor.execute(
                "INSERT INTO users (id, username, email, password_hash, tier, last_reset, api_key, audit_history) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                row + (None, "[]")
            )
        conn.commit()
        logger.info("Database migration completed")
    conn.close()

migrate_database()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === USAGE TRACKING ===
import os.path
USAGE_STATE_FILE = 'usage_state.json'
USAGE_COUNT_FILE = 'usage_count.txt'

level_map = {"free": 0, "beginner": 1, "pro": 2, "diamond": 3}

class UsageTracker:
    def __init__(self):
        self.count = 0
        self.last_reset = datetime.now()
        if os.path.exists(USAGE_STATE_FILE):
            with open(USAGE_STATE_FILE, 'r') as f:
                state = json.load(f)
            self.last_tier = state.get('last_tier', "free")
            self.last_change_time = datetime.fromisoformat(state.get('last_change_time', datetime.now().isoformat()))
        else:
            self.last_tier = "free"
            self.last_change_time = datetime.now()
            self._save_state()
        if os.path.exists(USAGE_COUNT_FILE):
            with open(USAGE_COUNT_FILE, 'r') as f:
                legacy_count = int(f.read().strip() or 0)
            if legacy_count > self.count:
                self.count = legacy_count
                self._save_state()
        self.size_limits = {"free": 1024 * 1024, "beginner": 1024 * 1024, "pro": 1024 * 1024, "diamond": float('inf')}
        self.feature_flags = {
            "free": {"diamond": False, "predictions": False, "onchain": False, "reports": False, "fuzzing": False},
            "beginner": {"diamond": False, "predictions": True, "onchain": True, "reports": True, "fuzzing": False},
            "pro": {"diamond": True, "predictions": True, "onchain": True, "reports": True, "fuzzing": True},
            "diamond": {"diamond": True, "predictions": True, "onchain": True, "reports": True, "fuzzing": True}
        }

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
                self.count = 0
                user.last_reset = current_time
                db.commit()
                logger.info(f"Downgraded {username} to free tier due to non-payment")
            if file_size > self.size_limits.get(user.tier, self.size_limits["free"]):
                raise HTTPException(status_code=400, detail=f"File size ({file_size / 1024 / 1024:.2f}MB) exceeds {user.tier} limit")
            self.count += 1
            user.last_reset = current_time
            db.commit()
            logger.info(f"UsageTracker incremented to: {self.count} for {username}, current tier: {user.tier}")
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
                raise HTTPException(status_code=400, detail=f"File size ({file_size / 1024 / 1024:.2f}MB) exceeds {current_tier} limit")
            self.count += 1
            self._save_state()
            limits = {"free": FREE_LIMIT, "beginner": BEGINNER_LIMIT, "pro": PRO_LIMIT, "diamond": PRO_LIMIT}
            if self.count > limits.get(current_tier, FREE_LIMIT):
                raise HTTPException(status_code=403, detail=f"Usage limit exceeded for {current_tier} tier. Limit is {limits.get(current_tier, FREE_LIMIT)}. Upgrade tier.")
            logger.info(f"UsageTracker incremented to: {self.count}, current tier: {current_tier}")
            return self.count

    def _save_state(self):
        state = {
            'count': self.count,
            'last_tier': self.last_tier,
            'last_change_time': self.last_change_time.isoformat()
        }
        with open(USAGE_STATE_FILE, 'w') as f:
            json.dump(state, f)
        with open(USAGE_COUNT_FILE, 'w') as f:
            f.write(str(self.count))

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

    def set_tier(self, tier: str, username: str = None, db: Session = None):
        if tier not in level_map:
            return f"Invalid tier: {tier}. Use 'free', 'beginner', 'pro', or 'diamond'"
        if username and db:
            user = db.query(User).filter(User.username == username).first()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            user.tier = tier
            user.last_reset = datetime.now()
            if tier == "pro":
                user.api_key = secrets.token_urlsafe(32)
            if tier == "diamond":
                user.tier = "pro"  # Grant 1-month Pro after Diamond
                user.last_reset = datetime.now() + timedelta(days=30)
            db.commit()
            logger.info(f"Set tier for {username} to {tier}")
        else:
            self.last_tier = tier
            self.last_change_time = datetime.now()
            os.environ["TIER"] = tier
            self._save_state()
            logger.info(f"Tier switched to: {tier}")
        return f"Switched to {tier} tier"

    def mock_purchase(self, tier: str, username: str = None, db: Session = None):
        if tier in level_map and level_map[tier] > level_map.get(self.last_tier, 0):
            result = self.set_tier(tier, username, db)
            self.count = 0
            return f"Purchase successful. {result}"
        return f"Purchase failed. Cannot downgrade from {self.last_tier} to {tier} or invalid tier."

usage_tracker = UsageTracker()
usage_tracker.set_tier("free")

FREE_LIMIT = 3
BEGINNER_LIMIT = 10
PRO_LIMIT = float('inf')

print("Initializing OpenAI and Web3 clients...")
@retry(stop_after_attempt(3), wait_fixed(2))
def initialize_client():
    print("Starting client initialization...")
    try:
        if not GROK_API_KEY or not INFURA_PROJECT_ID:
            print("Missing API keys, raising ValueError.")
            raise ValueError("Missing API keys in .env file. Please set GROK_API_KEY and INFURA_PROJECT_ID.")
        client = OpenAI(api_key=GROK_API_KEY, base_url="https://api.x.ai/v1")
        print("OpenAI client created successfully.")
        infura_url = f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}"
        w3 = Web3(Web3.HTTPProvider(infura_url))
        print("Web3 provider initialized.")
        if not w3.is_connected():
            print("Infura not connected, raising ConnectionError.")
            raise ConnectionError("Failed to connect to Ethereum via Infura. Check INFURA_PROJECT_ID.")
        print("Clients initialized successfully.")
        return client, w3
    except Exception as e:
        print(f"Initialization failed: {e}")
        logger.error(f"Client initialization failed: {str(e)}. Retrying...")
        raise

client, w3 = initialize_client()

app = FastAPI(title="DeFiGuard AI", description="Predictive DeFi Compliance Auditor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000"],
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

app.mount("/static", StaticFiles(directory="static"), name="static")

# CSRF Token Generation and Validation
def generate_csrf_token():
    return secrets.token_urlsafe(32)

async def get_csrf_token(request: Request):
    try:
        logger.debug(f"Processing get_csrf_token for session: {request.session}, headers: {request.headers}")
        token = request.session.get("csrf_token")
        if not token:
            token = generate_csrf_token()
            request.session["csrf_token"] = token
            logger.info(f"Generated new CSRF token: {token}")
        else:
            logger.debug(f"Reusing existing CSRF token: {token}")
        logger.debug("Flushing log file after CSRF token generation")
        handler.flush()
        return token
    except Exception as e:
        logger.error(f"Error generating CSRF token: {str(e)}")
        logger.debug("Flushing log file after CSRF error")
        handler.flush()
        raise HTTPException(status_code=500, detail=f"CSRF token generation failed: {str(e)}")

async def verify_csrf_token(request: Request):
    try:
        logger.debug(f"Verifying CSRF token for request: {request.method} {request.url}, headers: {request.headers}")
        if request.method in ["POST", "PUT", "DELETE"]:
            token = request.headers.get("X-CSRF-Token")
            if not token or token != request.session.get("csrf_token"):
                logger.error(f"CSRF validation failed: Provided={token}, Expected={request.session.get('csrf_token')}")
                logger.debug("Flushing log file after CSRF validation failure")
                handler.flush()
                raise HTTPException(status_code=403, detail="Invalid CSRF token")
        logger.debug("Flushing log file after CSRF verification")
        handler.flush()
        return True
    except Exception as e:
        logger.error(f"CSRF verification error: {str(e)}")
        logger.debug("Flushing log file after CSRF verification error")
        handler.flush()
        raise HTTPException(status_code=500, detail=f"CSRF verification failed: {str(e)}")

# Debug endpoint to test logging
@app.get("/debug")
async def debug_log():
    logger.debug("Debug endpoint called")
    logger.info("Test INFO log")
    logger.warning("Test WARNING log")
    logger.error("Test ERROR log")
    logger.debug("Flushing log file after debug endpoint")
    handler.flush()
    return {"message": "Debug logs written to debug.log"}

# Debug static file serving
@app.get("/static/{file_path:path}")
async def serve_static(file_path: str):
    logger.info(f"Serving static file: /static/{file_path}")
    logger.debug("Flushing log file after serving static file")
    handler.flush()
    return StaticFiles(directory="static").get_response(file_path)

# Reset usage for testing
@app.post("/reset-usage")
async def reset_usage(request: Request, username: str = Query(None), db: Session = Depends(get_db)):
    try:
        await verify_csrf_token(request)
        count = usage_tracker.reset_usage(username, db)
        logger.info(f"Usage reset to {count} for {username or 'anonymous'}")
        logger.debug("Flushing log file after usage reset")
        handler.flush()
        return {"message": f"Usage reset to {count} for {username or 'anonymous'}"}
    except HTTPException as e:
        logger.error(f"Reset usage HTTP error for {username or 'anonymous'}: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Reset usage unexpected error for {username or 'anonymous'}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to reset usage: {str(e)}")

@app.get("/ui", response_class=HTMLResponse)
async def read_ui():
    try:
        with open("templates/index.html", "r") as f:
            print(f"Loading UI from: {os.path.abspath('templates/index.html')}")
            logger.info(f"Loading UI from: {os.path.abspath('templates/index.html')}")
            logger.debug("Flushing log file after loading UI")
            handler.flush()
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        logger.error("UI file not found: templates/index.html")
        logger.debug("Flushing log file after UI file error")
        handler.flush()
        return HTMLResponse(content="<h1>UI file not found. Check templates/index.html.</h1>")

@app.get("/auth", response_class=HTMLResponse)
async def read_auth():
    try:
        with open("templates/auth.html", "r") as f:
            print(f"Loading auth from: {os.path.abspath('templates/auth.html')}")
            logger.info(f"Loading auth from: {os.path.abspath('templates/auth.html')}")
            logger.debug("Flushing log file after loading auth")
            handler.flush()
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        logger.error("Auth file not found: templates/auth.html")
        logger.debug("Flushing log file after auth file error")
        handler.flush()
        return HTMLResponse(content="<h1>Auth file not found. Check templates folder.</h1>")

@app.get("/csrf-token")
async def get_csrf(request: Request):
    try:
        logger.debug(f"Received /csrf-token request from {request.client.host}, headers: {request.headers}, cookies: {request.cookies}")
        token = await get_csrf_token(request)
        logger.info(f"Returning CSRF token: {token}")
        logger.debug("Flushing log file after returning CSRF token")
        handler.flush()
        return {"csrf_token": token}
    except Exception as e:
        logger.error(f"CSRF endpoint error: {str(e)}")
        logger.debug("Flushing log file after CSRF endpoint error")
        handler.flush()
        raise HTTPException(status_code=500, detail=f"Failed to generate CSRF token: {str(e)}")

@app.post("/signup/{username}")
async def signup(username: str, request: Request, db: Session = Depends(get_db)):
    await verify_csrf_token(request)
    if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
        raise HTTPException(status_code=400, detail="Username must be 3-20 alphanumeric characters or underscores")
    data = await request.json()
    email = data.get("email")
    password = data.get("password")
    if not email or not username or not password:
        raise HTTPException(status_code=400, detail="Email, username, and password are required")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = User(username=username, email=email, password_hash=password_hash, tier="free", last_reset=datetime.now(), api_key=None, audit_history="[]")
    db.add(user)
    db.commit()
    logger.info(f"User {username} signed up with free tier")
    logger.debug("Flushing log file after signup")
    handler.flush()
    return {"message": f"User {username} signed up with free tier"}

@app.post("/signin/{username}")
async def signin(username: str, request: Request, db: Session = Depends(get_db)):
    await verify_csrf_token(request)
    if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
        raise HTTPException(status_code=400, detail="Invalid username format")
    data = await request.json()
    password = data.get("password")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid password")
    logger.info(f"User {username} signed in")
    logger.debug("Flushing log file after signin")
    handler.flush()
    return {"message": f"Signed in as {username}"}

@app.get("/tier")
async def get_tier(username: str = Query(None), db: Session = Depends(get_db)):
    if username:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        user_tier = user.tier
        size_limit = "Unlimited" if user_tier == "diamond" else "1MB"
        feature_flags = usage_tracker.feature_flags[user_tier]
        api_key = user.api_key if user_tier == "pro" else None
    else:
        user_tier = os.getenv("TIER", "free")
        size_limit = "Unlimited" if user_tier == "diamond" else "1MB"
        feature_flags = usage_tracker.feature_flags[user_tier]
        api_key = None
    logger.debug(f"Retrieved tier for {username or 'anonymous'}: {user_tier}")
    logger.debug("Flushing log file after tier retrieval")
    handler.flush()
    return {
        "tier": user_tier,
        "size_limit": size_limit,
        "feature_flags": feature_flags,
        "api_key": api_key
    }

@app.post("/set-tier/{username}/{tier}")
async def set_tier(username: str, tier: str, request: Request, db: Session = Depends(get_db)):
    await verify_csrf_token(request)
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    result = usage_tracker.mock_purchase(tier, username, db)
    if "successful" in result:
        logger.info(f"Upgraded {username} to {tier} tier")
        logger.debug("Flushing log file after tier upgrade")
        handler.flush()
        return {"message": f"Upgraded {username} to {tier} tier"}
    raise HTTPException(status_code=400, detail=result)

@app.get("/upgrade")
async def upgrade_page():
    logger.debug("Upgrade page accessed")
    logger.debug("Flushing log file after upgrade page access")
    handler.flush()
    return {"message": "Upgrade at /ui for Beginner ($50/mo), Pro ($199/mo), or Diamond ($5k-$25k one-off)."}

@app.get("/facets/{contract_address}")
async def get_facets(contract_address: str, username: str = Query(None), db: Session = Depends(get_db)):
    try:
        logger.debug(f"Received /facets request for {contract_address} by {username or 'anonymous'}")
        if not w3.is_address(contract_address):
            logger.error(f"Invalid Ethereum address: {contract_address}")
            logger.debug("Flushing log file after invalid address")
            handler.flush()
            raise HTTPException(status_code=400, detail="Invalid Ethereum address")

        user = db.query(User).filter(User.username == username).first()
        current_tier = user.tier if user else os.getenv("TIER", "free")
        if current_tier not in ["pro", "diamond"]:
            logger.warning(f"Facet preview denied for {username or 'anonymous'} (tier: {current_tier})")
            logger.debug("Flushing log file after tier check failure")
            handler.flush()
            raise HTTPException(status_code=403, detail="Facet preview requires Pro or Diamond tier. Upgrade at /upgrade.")

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
        
        try:
            facets = contract.functions.facets().call()
            facet_data = [
                {
                    "facetAddress": facet[0],
                    "functionSelectors": [selector.hex() for selector in facet[1]][:2] if current_tier == "pro" else [selector.hex() for selector in facet[1]],
                    "functions": [selector[:10] for selector in facet[1]][:2] if current_tier == "pro" else [selector[:10] for selector in facet[1]]
                }
                for facet in facets
            ]
            logger.info(f"Retrieved {len(facet_data)} facets for {contract_address}")
            logger.debug("Flushing log file after fetching facets")
            handler.flush()
            return {"facets": facet_data, "is_preview": current_tier == "pro"}
        except Exception as e:
            logger.error(f"Failed to fetch facets for {contract_address}: {str(e)}")
            logger.debug("Flushing log file after facet fetch error")
            handler.flush()
            raise HTTPException(status_code=500, detail=f"Failed to fetch facets: {str(e)}")
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Unexpected error in /facets: {str(e)}")
        logger.debug("Flushing log file after unexpected /facets error")
        handler.flush()
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

def run_echidna(temp_path):
    """Run Echidna fuzzing on the Solidity file and return results."""
    try:
        subprocess.run(["docker", "pull", "trailofbits/echidna"], check=True, capture_output=True)
        config_path = os.path.join(os.getcwd(), "echidna_config.yaml")
        with open(config_path, "w") as f:
            f.write("""
format: text
testLimit: 10000
seqLen: 100
coverage: true
            """)
        output_path = os.path.join(os.getcwd(), "echidna_output")
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{os.getcwd()}:/app",
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
    except subprocess.TimeoutExpired:
        logger.error("Echidna fuzzing timed out after 300 seconds")
        return {"fuzzing_results": "Fuzzing timed out"}
    except Exception as e:
        logger.error(f"Echidna fuzzing failed: {str(e)}")
        return {"fuzzing_results": f"Fuzzing failed: {str(e)}"}
    finally:
        if os.path.exists(config_path):
            os.unlink(config_path)
        if os.path.exists(output_path):
            os.unlink(output_path)

@app.post("/upload-temp")
async def upload_temp(file: UploadFile = File(...), username: str = Query(...), db: Session = Depends(get_db), request: Request = None):
    await verify_csrf_token(request)
    user = db.query(User).filter(User.username == username).first()
    if not user or not usage_tracker.feature_flags[user.tier]["diamond"]:
        raise HTTPException(status_code=403, detail="Temporary file upload requires Diamond feature access")
    temp_id = str(uuid.uuid4())
    temp_dir = "temp_files"
    os.makedirs(temp_dir, exist_ok=True)
    temp_path = os.path.join(temp_dir, f"{temp_id}.sol")
    with open(temp_path, "wb") as f:
        f.write(await file.read())
    logger.info(f"Temporary file uploaded for {username}: {temp_id}")
    return {"temp_id": temp_id}

@app.post("/create-checkout-session")
async def create_checkout_session(username: str = Query(...), temp_id: str = Query(...), price: int = Query(...), request: Request = None, db: Session = Depends(get_db)):
    await verify_csrf_token(request)
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': 'Diamond Audit',
                    },
                    'unit_amount': price * 100,  # cents
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=f'http://127.0.0.1:8000/ui?session_id={{CHECKOUT_SESSION_ID}}&temp_id={temp_id}',
            cancel_url='http://127.0.0.1:8000/ui',
            metadata={'temp_id': temp_id, 'username': username}
        )
        logger.info(f"Stripe Checkout session created for {username} with temp_id {temp_id}")
        return {"session_url": session.url}
    except Exception as e:
        logger.error(f"Stripe session creation failed for {username}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create checkout session: {str(e)}")

@app.post("/webhook")
async def webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')
    event = None
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        logger.error(f"Stripe webhook error: Invalid payload - {str(e)}")
        return Response(status_code=400)
    except stripe.error.SignatureVerificationError as e:
        logger.error(f"Stripe webhook error: Invalid signature - {str(e)}")
        return Response(status_code=400)

    if event.type == 'checkout.session.completed':
        session = event.data.object
        username = session.metadata.username
        temp_id = session.metadata.temp_id
        logger.info(f"Payment completed for {username}, starting audit for temp_id {temp_id}")
        # Simulate starting audit (in real, use background task)
        # For test, log only
    return Response(status_code=200)

@app.get("/complete-diamond-audit")
async def complete_diamond_audit(session_id: str = Query(...), temp_id: str = Query(...), username: str = Query(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    try:
        session = stripe.checkout.Session.retrieve(session_id)
        if session.payment_status == 'paid':
            temp_path = os.path.join("temp_files", f"{temp_id}.sol")
            if not os.path.exists(temp_path):
                raise HTTPException(status_code=404, detail="Temporary file not found")
            with open(temp_path, "rb") as f:
                file = UploadFile(filename="temp.sol", file=f)
                result = await audit_contract(file, None, username, db, None)
            os.unlink(temp_path)
            logger.info(f"Diamond audit completed for {username} after payment")
            return result
        else:
            raise HTTPException(status_code=400, detail="Payment not completed")
    except Exception as e:
        logger.error(f"Complete diamond audit failed for {username}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to complete audit: {str(e)}")

@app.post("/diamond-audit")
async def diamond_audit(file: UploadFile = File(...), username: str = Query(...), db: Session = Depends(get_db), request: Request = None):
    await verify_csrf_token(request)
    user = db.query(User).filter(User.username == username).first()
    if not user or not usage_tracker.feature_flags[user.tier]["diamond"]:
        raise HTTPException(status_code=403, detail="Diamond audit requires Pro or Diamond tier")
    code_bytes = await file.read()
    file_size = len(code_bytes)
    if file_size > 50 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File size exceeds 50MB limit")
    price = usage_tracker.calculate_diamond_price(file_size)
    logger.info(f"Preparing Diamond audit for {username} at ${price} for file size {file_size / 1024 / 1024:.2f}MB")
    # For real Stripe, create session here, but for test, simulate and proceed
    # To implement real, replace with create_checkout_session call
    # For now, simulate
    logger.info(f"Mock Stripe payment for {username}")
    # Temporarily set tier to 'diamond' for size check
    original_tier = user.tier
    user.tier = 'diamond'
    db.commit()
    try:
        file.file.seek(0)
        result = await audit_contract(file, None, username, db, request)
    finally:
        user.tier = original_tier
        db.commit()
        logger.info(f"Reverted {username} to {original_tier} tier after Diamond audit")
    return {"price": price, "audit_result": result}

@app.get("/api/audit")
async def api_audit(username: str, api_key: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or user.api_key != api_key or user.tier != "pro":
        raise HTTPException(status_code=403, detail="API access requires Pro tier and valid API key")
    return {"message": "API audit endpoint (Pro tier)"}

@app.get("/", response_class=HTMLResponse)
async def read_root():
    logger.debug("Root endpoint accessed, redirecting to /ui")
    logger.debug("Flushing log file after root access")
    handler.flush()
    return HTMLResponse(content="<script>window.location.href='/ui';</script>")

class AuditReport(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    issues: list[dict] = Field(..., min_length=1)
    predictions: list[dict] = Field(..., min_length=0)
    recommendations: list[str] = Field(..., min_length=0)
    remediation_roadmap: Optional[str] = Field(None, description="Detailed remediation plan for Diamond tier")
    fuzzing_results: list[dict] = Field(default_factory=list, description="Echidna fuzzing results for Pro/Diamond tiers")

class AuditResponse(BaseModel):
    report: AuditReport
    risk_score: str | int

class AuditRequest(BaseModel):
    contract_address: str = None

AUDIT_SCHEMA = {
    "type": "object",
    "properties": {
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "issues": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "severity": {"type": "string", "enum": ["Low", "Med", "High"]},
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
                    "impact": {"type": "string", "enum": ["Low", "Med", "High"]}
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
    "required": ["risk_score", "issues", "predictions", "recommendations", "fuzzing_results"]
}

PROMPT_TEMPLATE = """
Analyze this Solidity code for vulnerabilities and 2025 regulations (MiCA, SEC FIT21).
Context: {context}.
Fuzzing Results: {fuzzing_results}.
Code: {code}.
Protocol Details: {details}.
Tier: {tier}.
Return the analysis in the exact JSON schema provided. For Beginner/Pro, include detailed predictions and recommendations. For Pro, add advanced regulatory insights and fuzzing results. For Diamond, include formal verification, exploit simulation, threat modeling, fuzzing results, and a remediation roadmap.
"""

@app.post("/audit", response_model=AuditResponse)
async def audit_contract(file: UploadFile = File(...), contract_address: str = None, username: str = Query(...), db: Session = Depends(get_db), request: Request = None):
    await verify_csrf_token(request)
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    code_bytes = await file.read()
    file_size = len(code_bytes)
    print(f"File read: {file_size} bytes ({file_size / 1024 / 1024:.2f}MB)")
    logger.debug(f"File read: {file_size} bytes for user {username}")
    current_count = usage_tracker.increment(file_size, username, db)
    current_tier = user.tier
    logger.info(f"Audit request {current_count} processed for contract {contract_address} with tier {current_tier} for user {username}")
    logger.debug("Flushing log file after audit request")
    handler.flush()

    raw_response = None
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open('debug.log', 'a') as f:
        f.write(f"[{timestamp}] Raw response logging attempt\n")
        f.flush()
    try:
        print("Starting audit process...")
        try:
            code_str = code_bytes.decode('utf-8')
        except UnicodeDecodeError as decode_err:
            logger.error(f"File decoding failed: {str(decode_err)}")
            logger.debug("Flushing log file after decode error")
            handler.flush()
            raise HTTPException(status_code=400, detail=f"File decoding failed: {str(decode_err)}")
        if not code_str.strip():
            logger.error("Empty file uploaded")
            logger.debug("Flushing log file after empty file error")
            handler.flush()
            raise HTTPException(status_code=400, detail="Empty file uploaded.")

        temp_path = None
        try:
            with NamedTemporaryFile(delete=False, suffix=".sol", dir=os.getcwd()) as temp_file:
                temp_file.write(code_bytes)
                temp_path = temp_file.name
                if platform.system() == "Windows":
                    temp_path = temp_path.replace("/", "\\")
            
            context = ""
            fuzzing_results = []
            try:
                print("Starting Slither analysis...")
                @retry(stop_after_attempt(3), wait_fixed(2))
                def analyze_slither(temp_path, attempt_number=1):
                    print(f"Slither retry attempt {attempt_number}")
                    return Slither(temp_path)
                slither = analyze_slither(temp_path, attempt_number=1)
                print("Slither analysis completed.")
                logger.info("Slither analysis completed successfully.")
                findings = []
                for contract in slither.contracts:
                    print(f"Processing contract: {contract.name}")
                    for detector in slither.detectors:
                        findings.extend(detector.detect())
                context = json.dumps([finding.to_json() for finding in findings]).replace('"', '\\"') if findings else "No static issues found"
            except SlitherError as e:
                print(f"Slither error details: {str(e)}")
                logger.error(f"Slither analysis failed: {str(e)}")
                logger.debug("Flushing log file after Slither error")
                handler.flush()
                context = "Slither analysis failed; proceeding with raw code"

            if usage_tracker.feature_flags[current_tier]["fuzzing"]:
                print("Starting Echidna fuzzing...")
                echidna_output = run_echidna(temp_path)
                fuzzing_results = [
                    {"vulnerability": "Potential issue", "description": echidna_output["fuzzing_results"]}
                ] if isinstance(echidna_output["fuzzing_results"], str) else echidna_output["fuzzing_results"]
                context += f"\nEchidna fuzzing results: {json.dumps(fuzzing_results)}"
            else:
                logger.info(f"Fuzzing skipped for {current_tier} tier")

            if contract_address and not usage_tracker.feature_flags[current_tier]["onchain"]:
                logger.warning(f"On-chain analysis denied for {username} (tier: {current_tier})")
                logger.debug("Flushing log file after onchain tier check")
                handler.flush()
                raise HTTPException(status_code=403, detail="On-chain analysis requires Beginner or higher tier.")

            details = "Uploaded Solidity code for analysis."
            if contract_address:
                if not w3.is_address(contract_address):
                    logger.error(f"Invalid Ethereum address: {contract_address}")
                    logger.debug("Flushing log file after invalid address")
                    handler.flush()
                    raise HTTPException(status_code=400, detail="Invalid Ethereum address.")
                onchain_code = w3.eth.get_code(contract_address)
                if onchain_code:
                    details += f" On-chain code fetched for {contract_address} (bytecode length: {len(onchain_code)})."
                else:
                    details += f" No deployed code found at {contract_address}."

            if current_tier == "diamond" and file_size > 1024 * 1024:
                chunks = [code_str[i:i+500000] for i in range(0, len(code_str), 500000)]
                results = []
                for i, chunk in enumerate(chunks):
                    print(f"Processing chunk {i+1}/{len(chunks)}...")
                    prompt = PROMPT_TEMPLATE.format(context=context, fuzzing_results=json.dumps(fuzzing_results), code=chunk, details=details, tier=current_tier)
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
                        results.append(json.loads(response.choices[0].message.content))
                aggregated = {
                    "risk_score": max(r["risk_score"] for r in results),
                    "issues": sum([r["issues"] for r in results], []),
                    "predictions": sum([r["predictions"] for r in results], []),
                    "recommendations": sum([r["recommendations"] for r in results], []),
                    "remediation_roadmap": "Detailed plan: Prioritize high-severity issues, implement fixes, and schedule manual review.",
                    "fuzzing_results": fuzzing_results
                }
                user = db.query(User).filter(User.username == username).first()
                if user:
                    history = json.loads(user.audit_history)
                    history.append({"contract": contract_address or "uploaded", "timestamp": datetime.now().isoformat(), "risk_score": aggregated["risk_score"]})
                    user.audit_history = json.dumps(history)
                    db.commit()
                return {"report": aggregated, "risk_score": str(aggregated["risk_score"])}

            print("Calling Grok API...")
            prompt = PROMPT_TEMPLATE.format(context=context, fuzzing_results=json.dumps(fuzzing_results), code=code_str, details=details, tier=current_tier)
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
            print("API response received.")

            if response.choices and response.choices[0].message.content:
                raw_response = response.choices[0].message.content
                print(f"DEBUG: Raw Grok Response: {raw_response}", file=sys.stdout, flush=True)
                with open('debug.log', 'a') as f:
                    f.write(f"[{timestamp}] DEBUG: Raw Grok Response: {raw_response}\n")
                    f.flush()
                logger.info(f"Raw Grok Response: {raw_response}")
                audit_json = json.loads(raw_response)
                if current_tier == "diamond":
                    audit_json["remediation_roadmap"] = "Detailed plan: Prioritize high-severity issues, implement fixes, and schedule manual review."
                audit_json["fuzzing_results"] = fuzzing_results
                user = db.query(User).filter(User.username == username).first()
                if user:
                    history = json.loads(user.audit_history)
                    history.append({"contract": contract_address or "uploaded", "timestamp": datetime.now().isoformat(), "risk_score": audit_json["risk_score"]})
                    user.audit_history = json.dumps(history)
                    db.commit()
                logger.debug("Flushing log file after successful audit")
                handler.flush()
                return {"report": audit_json, "risk_score": str(audit_json.get("risk_score", "N/A"))}
            else:
                logger.error("No response from Grok API")
                logger.debug("Flushing log file after no API response")
                handler.flush()
                raise HTTPException(status_code=500, detail="No response from Grok API")
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
    except Exception as e:
        print(f"Audit process failed: {str(e)}")
        if raw_response is not None:
            print(f"DEBUG: Error Raw Response: {raw_response}", file=sys.stdout, flush=True)
            with open('debug.log', 'a') as f:
                f.write(f"[{timestamp}] DEBUG: Error Raw Response: {raw_response}\n")
                f.flush()
            logger.error(f"Error Raw Grok Response: {raw_response}")
        logger.error(f"Audit error: {str(e)}")
        logger.debug("Flushing log file after audit error")
        handler.flush()
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

def handle_tool_call(tool_call):
    if tool_call.function.name == "fetch_reg":
        return {"result": "Sample reg data: SEC FIT21 requires custody audits."}
    return {"error": "Unknown tool"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
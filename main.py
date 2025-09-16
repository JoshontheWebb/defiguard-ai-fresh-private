# === IMPORTS ===
import os
import json
import logging
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from openai import OpenAI
from slither.slither import Slither
from slither.exceptions import SlitherError
from web3 import Web3
from pydantic import BaseModel, Field
from dotenv import load_dotenv, dotenv_values
from tempfile import NamedTemporaryFile
import re
import platform
import sys
from datetime import datetime, timedelta  # Updated for tier change timing
import time  # Added for retry backoff

# === ENVIRONMENT AND LOGGING ===
load_dotenv()
GROK_API_KEY = os.getenv("GROK_API_KEY")
INFURA_PROJECT_ID = os.getenv("INFURA_PROJECT_ID")

if not GROK_API_KEY or not INFURA_PROJECT_ID:
    raise ValueError("Missing API keys in .env file. Please set GROK_API_KEY and INFURA_PROJECT_ID.")

try:
    with open('debug.log', 'a') as f:
        f.write("Logging initialized at " + str(os.times()) + "\n")
except Exception as e:
    print(f"Error initializing log file: {e}", file=sys.stderr)
logging.basicConfig(level=logging.INFO, filename='debug.log', filemode='a')
logger = logging.getLogger(__name__)

# === USAGE TRACKING ===
import os.path
USAGE_STATE_FILE = 'usage_state.json'  # Store count, last_tier, last_change_time
USAGE_COUNT_FILE = 'usage_count.txt'   # Legacy file for compatibility

level_map = {"free": 0, "starter": 1, "pro": 2}

class UsageTracker:
    def __init__(self):
        if os.path.exists(USAGE_STATE_FILE):
            with open(USAGE_STATE_FILE, 'r') as f:
                state = json.load(f)
            self.count = state.get('count', 0)
            self.last_tier = state.get('last_tier', "free")
            self.last_change_time = datetime.fromisoformat(state.get('last_change_time', datetime.now().isoformat()))
        else:
            self.count = 0
            self.last_tier = "free"
            self.last_change_time = datetime.now()
            self._save_state()
        # Sync with legacy file
        if os.path.exists(USAGE_COUNT_FILE):
            with open(USAGE_COUNT_FILE, 'r') as f:
                legacy_count = int(f.read().strip() or 0)
            if legacy_count > self.count:
                self.count = legacy_count
                self._save_state()
        logger.info(f"UsageTracker initialized with count: {self.count}, tier: {self.last_tier}, last change: {self.last_change_time}")

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

    def increment(self):
        env = dotenv_values(".env")  # Reload .env on each call
        current_tier = env.get("TIER", "free")
        current_time = datetime.now()
        if current_tier != self.last_tier:
            old_level = level_map.get(self.last_tier, 0)
            new_level = level_map.get(current_tier, 0)
            days_since_change = (current_time - self.last_change_time).days
            if new_level > old_level:  # Upgrade
                logger.info(f"Upgrade detected from {self.last_tier} to {current_tier}, resetting count")
                self.count = 0
            elif new_level < old_level:  # Downgrade
                if days_since_change > 30:
                    logger.info(f"Downgrade from {self.last_tier} to {current_tier} after 30+ days, resetting count")
                    self.count = 0
                else:
                    logger.info(f"Downgrade from {self.last_tier} to {current_tier} within 30 days, keeping count")
            self.last_tier = current_tier
            self.last_change_time = current_time
            self._save_state()
        self.count += 1
        self._save_state()
        limits = {"free": FREE_LIMIT, "starter": STARTER_LIMIT, "pro": PRO_LIMIT}
        if self.count > limits.get(current_tier, FREE_LIMIT):
            raise HTTPException(status_code=403, detail=f"Usage limit exceeded for {current_tier} tier. Limit is {limits.get(current_tier, FREE_LIMIT)}. Upgrade at https://x.ai/grok")
        logger.info(f"UsageTracker incremented to: {self.count}, current tier: {current_tier}")
        return self.count

usage_tracker = UsageTracker()
FREE_LIMIT = 3
STARTER_LIMIT = 10
PRO_LIMIT = float('inf')  # Unlimited

# === CLIENT INITIALIZATION ===
client = OpenAI(api_key=GROK_API_KEY, base_url="https://api.x.ai/v1")
infura_url = f"https://mainnet.infura.io/v3/{INFURA_PROJECT_ID}"
w3 = Web3(Web3.HTTPProvider(infura_url))
if not w3.is_connected():
    raise ConnectionError("Failed to connect to Ethereum via Infura. Check INFURA_PROJECT_ID.")

app = FastAPI(title="DeFiGuard AI", description="Predictive DeFi Compliance Auditor")

# === RESPONSE MODELS ===
class AuditReport(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    issues: list[dict] = Field(..., min_length=1)
    predictions: list[dict] = Field(..., min_length=1)
    recommendations: list[str] = Field(..., min_length=1)

class AuditResponse(BaseModel):
    report: AuditReport
    risk_score: str | int

class AuditRequest(BaseModel):
    contract_address: str = None  # Optional: For on-chain queries

# === JSON SCHEMA ===
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
        "recommendations": {"type": "array", "items": {"type": "string"}}
    },
    "required": ["risk_score", "issues", "predictions", "recommendations"]
}

# === PROMPT TEMPLATE ===
PROMPT_TEMPLATE = """
Analyze this Solidity code for vulnerabilities and 2025 regulations (MiCA, SEC FIT21).
Context: {context}.
Code: {code}.
Protocol Details: {details}.
Return the analysis in the exact JSON schema provided.
"""

# === AUDIT ENDPOINT ===
@app.post("/audit", response_model=AuditResponse)
async def audit_contract(file: UploadFile = File(...), contract_address: str = None):
    # === USAGE ENFORCEMENT ===
    current_count = usage_tracker.increment()
    current_tier = os.getenv("TIER", "free")
    logger.info(f"Audit request {current_count} processed for contract {contract_address} with tier {current_tier}")

    raw_response = None  # Initialize to avoid UnboundLocalError
    # Log raw response immediately with timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open('debug.log', 'a') as f:  # 'a' ensures append
        f.write(f"[{timestamp}] Raw response logging attempt\n")
    try:
        # Read uploaded file (Solidity code)
        code_bytes = await file.read()
        code_str = code_bytes.decode('utf-8')
        if not code_str.strip():
            raise HTTPException(status_code=400, detail="Empty file uploaded.")

        # Step 1: Pre-scan with Slither (Windows-compatible)
        with NamedTemporaryFile(delete=False, suffix=".sol", dir=os.getcwd()) as temp_file:
            temp_file.write(code_bytes)
            temp_path = temp_file.name
            if platform.system() == "Windows":
                temp_path = temp_path.replace("/", "\\")
        try:
            slither = Slither(temp_path)
            findings = []
            for contract in slither.contracts:
                for detector in slither.detectors:
                    findings.extend(detector.detect())
            context = json.dumps([finding.to_json() for finding in findings]).replace('"', '\\"') if findings else "No static issues found"
        except SlitherError as e:
            logger.warning(f"Slither error: {e}")
            context = "Slither analysis failed; proceeding with raw code"
        finally:
            os.unlink(temp_path)  # Clean up

        # Step 2: Blockchain context if address provided
        details = "Uploaded Solidity code for analysis."
        if contract_address:
            if not w3.is_address(contract_address):
                raise HTTPException(status_code=400, detail="Invalid Ethereum address.")
            onchain_code = w3.eth.get_code(contract_address)
            if onchain_code:
                details += f" On-chain code fetched for {contract_address} (bytecode length: {len(onchain_code)})."
            else:
                details += f" No deployed code found at {contract_address}."

        # Step 3: Call Grok API with Structured Output
        prompt = PROMPT_TEMPLATE.format(context=context, code=code_str, details=details)
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

        # Step 4: Handle response (structured output is always JSON)
        if response.choices and response.choices[0].message.content:
            raw_response = response.choices[0].message.content
            print(f"DEBUG: Raw Grok Response: {raw_response}", file=sys.stdout, flush=True)
            with open('debug.log', 'a') as f:
                f.write(f"[{timestamp}] DEBUG: Raw Grok Response: {raw_response}\n")
            logger.info(f"Raw Grok Response: {raw_response}")
            # Structured output is valid JSON, so direct parsing
            try:
                audit_json = json.loads(raw_response)
                return {"report": audit_json, "risk_score": str(audit_json.get("risk_score", "N/A"))}
            except json.JSONDecodeError as e:
                logger.error(f"JSON Decode Error: {e} - Raw response: {raw_response}")
                raise HTTPException(status_code=500, detail=f"Invalid JSON from Grok API: {raw_response}")
        else:
            raise HTTPException(status_code=500, detail="No response from Grok API")

    except Exception as e:
        if raw_response is not None:
            print(f"DEBUG: Error Raw Response: {raw_response}", file=sys.stdout, flush=True)
            with open('debug.log', 'a') as f:
                f.write(f"[{timestamp}] DEBUG: Error Raw Response: {raw_response}\n")
            logger.error(f"Error Raw Grok Response: {raw_response}")
        logger.error(f"Audit error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")

# === TOOL HANDLING ===
def handle_tool_call(tool_call):
    if tool_call.function.name == "fetch_reg":
        return {"result": "Sample reg data: SEC FIT21 requires custody audits."}
    return {"error": "Unknown tool"}

# === MAIN EXECUTION ===
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
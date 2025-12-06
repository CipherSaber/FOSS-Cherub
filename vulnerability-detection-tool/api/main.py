# main.py - COMPLETE WITH CWE CLASSIFICATION

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
import logging
from typing import List
from contextlib import asynccontextmanager
import re  # ADD THIS

MODEL_PATH = "/workspace/vulnerability-detection-tool/data_processing/merged_model"
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
tokenizer, model = None, None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global tokenizer, model
    logger.info(f"Loading model from {MODEL_PATH}...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        torch_dtype=torch.bfloat16,
        device_map="auto"
    )
    logger.info("✅ Model loaded successfully")
    yield

app = FastAPI(title="Vulnerability Detection API with CWE Classification", lifespan=lifespan)

# ==================== MODELS ====================
class CodeInput(BaseModel):
    id: str
    code: str
    language: str

class MitigationRequest(BaseModel):
    file_content: str
    line_number: int
    vulnerability: str
    language: str

class CWEClassificationRequest(BaseModel):  # NEW MODEL
    vulnerability: str
    code_snippet: str = ""
    severity: str = "MEDIUM"

# ==================== HELPER ====================
def extract_assistant_response(full_response: str) -> str:
    """Extract ONLY the assistant's response"""
    if "assistant" in full_response.lower():
        parts = full_response.split("assistant")
        if len(parts) > 1:
            response = parts[-1].strip()
            response = response.lstrip('\n\r ')
            if response:
                return response

    markers = ["\nassistant\n", "assistant:", "Assistant:", "Response:"]
    for marker in markers:
        if marker in full_response:
            response = full_response.split(marker)[-1].strip()
            if response and len(response) < len(full_response):
                return response

    if full_response.startswith("system"):
        lines = full_response.split('\n')
        response_started = False
        response_lines = []

        for line in lines:
            line_lower = line.lower().strip()
            if line_lower == 'assistant' or line_lower.startswith('assistant'):
                response_started = True
                continue
            if response_started:
                response_lines.append(line)

        if response_lines:
            return '\n'.join(response_lines).strip()

    return full_response[-200:].strip()

# ==================== PROMPTS ====================
def create_analysis_prompt(code: str, language: str) -> str:
    return f"""system
You are an expert security analyst. Analyze the code for vulnerabilities. Respond with "Vulnerable" and the CWE ID if a flaw exists, or "Not Vulnerable".

user
Analyze this {language} code:

{code[:1500]}

assistant"""

def create_mitigation_prompt(file_content: str, vulnerability: str, language: str, line_number: int) -> str:
    return f"""system
You are a security engineer. Provide a fix for this vulnerability.

Your response MUST include:
## Vulnerability Explanation
[Explain the risk]

## Vulnerable Code
[Show insecure code]

## Fixed Code
[Show secure code]

user
Fix this {language} vulnerability: {vulnerability}

Code (around line {line_number}):
{file_content[:1500]}

assistant"""

def create_cwe_classification_prompt(vulnerability: str, severity: str, code_snippet: str = "") -> str:
    """Prompt for CWE classification"""
    return f"""system
You are a CWE classification expert. Analyze the vulnerability and respond with ONLY the most appropriate CWE ID.

Common CWE IDs:
CWE-89: SQL Injection
CWE-79: XSS
CWE-78: Command Injection
CWE-22: Path Traversal
CWE-502: Deserialization
CWE-120: Buffer Overflow
CWE-798: Hard-coded Credentials
CWE-327: Weak Cryptography
CWE-95: Code Injection (eval)
CWE-611: XXE
CWE-918: SSRF
CWE-287: Improper Authentication
CWE-352: CSRF
CWE-434: File Upload

user
Vulnerability: {vulnerability}
Severity: {severity}
Code: {code_snippet[:200] if code_snippet else "Not provided"}

Respond in this EXACT format: CWE-XXX

assistant"""

# ==================== ENDPOINTS ====================

@app.post("/analyze_batch")
async def analyze_code_batch(items: List[CodeInput]):
    """Analyze code files for vulnerabilities"""
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    results = {}

    for item in items:
        try:
            prompt = create_analysis_prompt(item.code, item.language)

            inputs = tokenizer(
                prompt,
                return_tensors="pt",
                truncation=True,
                max_length=2048
            ).to(model.device)

            with torch.no_grad():
                outputs = model.generate(
                    **inputs,
                    max_new_tokens=200,
                    temperature=0.7,
                    do_sample=True,
                    top_p=0.9,
                    pad_token_id=tokenizer.eos_token_id
                )

            full_response = tokenizer.decode(outputs[0], skip_special_tokens=True)
            clean_response = extract_assistant_response(full_response)

            logger.info(f"File: {item.id} - Response: {clean_response[:100]}...")
            results[item.id] = clean_response

            if "vulnerable" in clean_response.lower():
                logger.info(f"✅ VULNERABILITY DETECTED in {item.id}")

        except Exception as e:
            logger.error(f"Error analyzing {item.id}: {e}")
            results[item.id] = "Error during analysis"

    return {"llm_analyses": results}

@app.post("/get_mitigation")
async def get_mitigation(req: MitigationRequest):
    """Generate mitigation for vulnerability"""
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        prompt = create_mitigation_prompt(
            req.file_content,
            req.vulnerability,
            req.language,
            req.line_number
        )

        inputs = tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=2048
        ).to(model.device)

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=1024,
                temperature=0.7,
                do_sample=True,
                top_p=0.9,
                pad_token_id=tokenizer.eos_token_id
            )

        full_response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        clean_mitigation = extract_assistant_response(full_response)

        logger.info(f"Generated mitigation: {len(clean_mitigation)} chars")

        return {"mitigation": clean_mitigation}

    except Exception as e:
        logger.error(f"Error generating mitigation: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/classify_cwe")  # NEW ENDPOINT
async def classify_cwe(req: CWEClassificationRequest):
    """Classify vulnerability to CWE using AI"""
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    try:
        prompt = create_cwe_classification_prompt(
            req.vulnerability,
            req.severity,
            req.code_snippet
        )

        inputs = tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=1024
        ).to(model.device)

        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=50,
                temperature=0.3,  # Lower temp for more deterministic
                do_sample=True,
                top_p=0.9,
                pad_token_id=tokenizer.eos_token_id
            )

        full_response = tokenizer.decode(outputs[0], skip_special_tokens=True)
        clean_response = extract_assistant_response(full_response)

        # Extract CWE-XXX from response
        cwe_match = re.search(r'CWE-\d+', clean_response, re.IGNORECASE)

        if cwe_match:
            cwe_id = cwe_match.group(0).upper()
            logger.info(f"✓ Classified: {req.vulnerability[:50]}... → {cwe_id}")
            return {"cwe_id": cwe_id, "confidence": "high"}
        else:
            logger.warning(f"No CWE found in: {clean_response}")
            return {"cwe_id": "N/A", "confidence": "low"}

    except Exception as e:
        logger.error(f"CWE classification error: {e}")
        return {"cwe_id": "N/A", "error": str(e)}

@app.get("/")
def read_root():
    return {
        "status": "Vulnerability Detection API is running",
        "endpoints": ["/analyze_batch", "/get_mitigation", "/classify_cwe"]
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "model_loaded": model is not None,
        "tokenizer_loaded": tokenizer is not None
    }

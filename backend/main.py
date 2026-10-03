from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import os
import sqlite3
from datetime import datetime
import json
import copy

from app.engines.risk_engine import Asset, Vulnerability, SecurityControl, calculate_enterprise_risk, calculate_asset_risk, simulate_monte_carlo_risk
from app.engines.optimizer import RemediationTask, optimize_budget_allocation
from app.routers.ai_advisor import router as advisor_router
from app.engines.blockchain import audit_blockchain

app = FastAPI(title="RNC: Relegate & Celebrate API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(advisor_router)

# In-memory store for asset valuation overrides
asset_overrides = {}

# Initialize SQLite Database for Audit Logs
def init_db():
    conn = sqlite3.connect("rnc_audit.db")
    cursor = conn.cursor()
    cursor.execute('DROP TABLE IF EXISTS audit_logs')
    cursor.execute('''
        CREATE TABLE audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ransomware_budget REAL,
            cloud_budget REAL,
            supply_chain_budget REAL,
            total_budget REAL,
            allocated REAL DEFAULT 0,
            risk_exposure REAL,
            optimization_index TEXT,
            block_hash TEXT,
            previous_hash TEXT
        );
    ''')
    conn.commit()
    conn.close()

init_db()

class OptimizationRequest(BaseModel):
    ransomwareBudget: float
    cloudBudget: float
    supplyChainBudget: float

def load_seed_data():
    with open("seed_data.json", "r") as f:
        data = json.load(f)
    
    assets = []
    assets_dict = {}
    for a in data["assets"]:
        # Apply override if exists
        fin_val = asset_overrides.get(a["asset_id"], a["financial_value"])
        vulns = [Vulnerability(**v) for v in a["vulnerabilities"]]
        controls = [SecurityControl(**c) for c in a["controls"]]
        asset = Asset(
            asset_id=a["asset_id"],
            name=a["name"],
            financial_value=fin_val,
            criticality_weight=a["criticality_weight"],
            vulnerabilities=vulns,
            controls=controls
        )
        assets.append(asset)
        assets_dict[a["asset_id"]] = asset
    
    tasks = []
    for t in data["candidate_projects"]:
        target_asset_id = t["target_asset_id"]
        new_control = SecurityControl(**t["new_control"])
        
        asset = assets_dict.get(target_asset_id)
        if asset:
            baseline_risk = calculate_asset_risk(asset).total_residual_eal
            asset_with_control = copy.deepcopy(asset)
            asset_with_control.controls.append(new_control)
            new_risk = calculate_asset_risk(asset_with_control).total_residual_eal
            risk_reduction = baseline_risk - new_risk
        else:
            risk_reduction = 0.0

        tasks.append(RemediationTask(
            task_id=t["task_id"],
            name=t["name"],
            cost=t["cost"],
            risk_reduction=max(0.0, risk_reduction),
            category=t["category"],
            target_asset=asset.name if asset else None,
            cve_id=t.get("cve_id"),
            compliance_tags=t.get("compliance_tags", [])
        ))
    return assets, tasks, data["candidate_projects"]

@app.get("/")
def read_root():
    return {"status": "online", "message": "RNC Backend Engine Active"}

@app.get("/api/assets")
def get_assets():
    with open("seed_data.json", "r") as f:
        data = json.load(f)
    for asset in data["assets"]:
        if asset["asset_id"] in asset_overrides:
            asset["financial_value"] = asset_overrides[asset["asset_id"]]
    return {"assets": data["assets"]}

class AssetUpdateRequest(BaseModel):
    asset_id: str
    financial_value: float = Field(ge=100000, description="Minimum asset value is ₹1,00,000")

@app.post("/api/assets")
def update_assets(updates: list[AssetUpdateRequest]):
    for u in updates:
        asset_overrides[u.asset_id] = u.financial_value
    return {"status": "success"}

@app.post("/api/assets/reset")
def reset_assets():
    asset_overrides.clear()
    return {"status": "success"}

@app.post("/api/optimize")
def optimize_risk(data: OptimizationRequest):
    total_budget = data.ransomwareBudget + data.cloudBudget + data.supplyChainBudget
    
    assets, tasks, raw_candidate_projects = load_seed_data()
    baseline_enterprise_risk = calculate_enterprise_risk(assets)
    baseline_exposure = baseline_enterprise_risk.total_residual_eal
    
    valid_tasks = [t for t in tasks if t.risk_reduction > t.cost]
    opt_result = optimize_budget_allocation(budget=total_budget, tasks=valid_tasks, method="exact")
    
    # Construct mitigated assets to recompute TRUE combined EAL and handle overlapping projects
    mitigated_assets = copy.deepcopy(assets)
    selected_task_ids = {t.task_id for t in opt_result.selected_tasks}
    
    for proj in raw_candidate_projects:
        if proj["task_id"] in selected_task_ids:
            target_asset = next((a for a in mitigated_assets if a.asset_id == proj["target_asset_id"]), None)
            if target_asset:
                target_asset.controls.append(SecurityControl(**proj["new_control"]))
                
    # Recompute adjusted exposure exactly
    adjusted_exposure = calculate_enterprise_risk(mitigated_assets).total_residual_eal
    true_risk_reduction = max(0.0, baseline_exposure - adjusted_exposure)
    total_cost = opt_result.metrics.total_investment_cost
    true_rosi = ((true_risk_reduction - total_cost) / total_cost * 100) if total_cost > 0 else 0
    
    # Update metrics in opt_result to reflect the non-double-counted values
    opt_result.metrics.total_risk_reduction = true_risk_reduction
    opt_result.metrics.net_financial_benefit = true_risk_reduction - total_cost
    opt_result.metrics.rosi_percentage = true_rosi
    opt_result.metrics.benefit_cost_ratio = (true_risk_reduction / total_cost) if total_cost > 0 else 0.0
    
    grade = "A+" if true_rosi >= 200 else ("A" if true_rosi >= 100 else ("B" if true_rosi >= 50 else "C"))
    optimization_index = f"{grade} ({true_rosi:.1f}%)"
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                
    mc_results = simulate_monte_carlo_risk(mitigated_assets, iterations=5000)

    # 1. Add to Blockchain
    block_data = {
        "timestamp": timestamp,
        "total_budget": total_budget,
        "risk_exposure": adjusted_exposure,
        "optimization_index": optimization_index,
        "selected_tasks": [t.task_id for t in opt_result.selected_tasks],
        "monte_carlo_p95": mc_results["p95_loss"]
    }
    new_block = audit_blockchain.add_block(block_data)

    # 2. Add to SQLite
    conn = sqlite3.connect("rnc_audit.db")
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO audit_logs (timestamp, ransomware_budget, cloud_budget, supply_chain_budget, total_budget, allocated, risk_exposure, optimization_index, block_hash, previous_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, data.ransomwareBudget, data.cloudBudget, data.supplyChainBudget, total_budget, total_cost, adjusted_exposure, optimization_index, new_block.hash, new_block.previous_hash))
    conn.commit()
    conn.close()

    formatted_tasks = [t.to_dict() for t in opt_result.selected_tasks]
    unselected_formatted = [t.to_dict() for t in opt_result.unselected_tasks]
    
    msg = "No project is cost-justified at current asset values" if not valid_tasks else ""

    return {
        "status": "success",
        "riskExposure": adjusted_exposure,
        "optimizationIndex": optimization_index,
        "selected_tasks": formatted_tasks,
        "unselected_tasks": unselected_formatted,
        "message": msg,
        "budget": total_budget,
        "allocated": total_cost,
        "unspent": total_budget - total_cost,
        "monte_carlo": mc_results,
        "block_hash": new_block.hash
    }
@app.get("/api/baseline")
def get_baseline():
    assets, tasks, raw = load_seed_data()
    baseline_enterprise_risk = calculate_enterprise_risk(assets)
    baseline_exposure = baseline_enterprise_risk.total_residual_eal
    mc_results = simulate_monte_carlo_risk(assets, iterations=5000)
    return {
        "riskExposure": baseline_exposure,
        "monte_carlo": mc_results
    }

@app.get("/api/audits")
def get_audit_logs():
    conn = sqlite3.connect("rnc_audit.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 10')
    rows = cursor.fetchall()
    conn.close()
    return {"logs": [dict(row) for row in rows]}

@app.get("/api/blockchain/verify")
def verify_blockchain():
    is_valid = audit_blockchain.is_chain_valid()
    blocks = []
    for block in audit_blockchain.chain:
        blocks.append({
            "index": block.index,
            "hash": block.hash,
            "previous_hash": block.previous_hash,
            "data": block.data
        })
    return {
        "status": "success" if is_valid else "tampered",
        "is_valid": is_valid,
        "chain_length": len(blocks),
        "blocks": blocks
    }

@app.get("/api/export-report", response_class=PlainTextResponse)
def export_executive_report():
    conn = sqlite3.connect("rnc_audit.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 5')
    rows = cursor.fetchall()
    conn.close()

    report = "====================================================\n"
    report += "       RNC: RELEGATE & CELEBRATE\n"
    report += "       EXECUTIVE CYBER-RISK QUANTIFICATION BRIEFING\n"
    report += "       [IMMUTABLE BLOCKCHAIN AUDIT TRAIL]\n"
    report += "====================================================\n\n"
    report += f"Generated At: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += f"Blockchain Integrity: {'VALID' if audit_blockchain.is_chain_valid() else 'COMPROMISED'}\n\n"
    report += "--- RECENT SIMULATION AUDIT TRAIL ---\n"
    
    if not rows:
        report += "No simulation logs recorded yet.\n"
    else:
        for row in rows:
            report += f"[{row['timestamp']}] \n"
            report += f"  - Total Capital:   ₹{row['total_budget']:,.2f}\n"
            report += f"  - Risk Exposure:   ₹{row['risk_exposure']:,.2f}\n"
            report += f"  - Index Grade:     {row['optimization_index']}\n"
            report += f"  - Block Hash:      {row['block_hash']}\n"
            report += "----------------------------------------------------\n"
            
    return report
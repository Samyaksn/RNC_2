"""
AI Decision Support Router - Quantitative Cyber Risk Advisor
=============================================================
Author: Backend API Developer
Module: app.routers.ai_advisor

This FastAPI router powers the AI Decision Support layer of the Cyber Risk Platform.
It accepts natural language questions from executives and security leaders, aggregates
real-time quantitative risk context (Single Loss Expectancy, Annualized Rate of
Occurrence, Expected Annual Loss, and control mitigations), and prompts Google Gemini
to deliver plain-English executive summaries and actionable risk guidance.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(tags=["AI Decision Support"])

class AIQueryRequest(BaseModel):
    question: str = Field(
        ...,
        description="Natural language question regarding enterprise risk posture.",
        example="What is our highest financial risk today and how are our controls performing?"
    )
    include_context: bool = Field(
        default=True,
        description="Whether to inject current enterprise quantitative risk context into the model."
    )

class RiskContextSummary(BaseModel):
    total_financial_exposure: float
    total_inherent_eal: float
    total_residual_eal: float
    annual_risk_mitigated: float
    overall_mitigation_rate: float
    top_risk_assets: List[Dict[str, Any]]

class AIQueryResponse(BaseModel):
    question: str
    executive_summary: str
    context_used: Optional[RiskContextSummary] = None
    model_used: str
    status: str = "success"

def gather_risk_context() -> RiskContextSummary:
    from app.engines.risk_engine import (
        calculate_enterprise_risk,
    )
    import main

    assets, _, _ = main.load_seed_data()
    summary = calculate_enterprise_risk(assets)
    
    top_assets_info = []
    for asset_risk in summary.top_risk_assets:
        top_assets_info.append({
            "asset_id": asset_risk.asset_id,
            "asset_name": asset_risk.asset_name,
            "financial_value": asset_risk.financial_value,
            "criticality_weight": asset_risk.criticality_weight,
            "inherent_eal": asset_risk.total_inherent_eal,
            "residual_eal": asset_risk.total_residual_eal,
            "mitigation_percentage": asset_risk.risk_mitigation_percentage,
            "top_cve": asset_risk.vulnerability_details[0].cve_id if asset_risk.vulnerability_details else "N/A",
            "cvss_score": asset_risk.vulnerability_details[0].cvss_score if asset_risk.vulnerability_details else 0.0
        })

    return RiskContextSummary(
        total_financial_exposure=summary.total_financial_value,
        total_inherent_eal=summary.total_inherent_eal,
        total_residual_eal=summary.total_residual_eal,
        annual_risk_mitigated=summary.total_annual_risk_mitigated,
        overall_mitigation_rate=summary.overall_mitigation_percentage,
        top_risk_assets=top_assets_info,
    )

def format_risk_context_for_prompt(context: RiskContextSummary) -> str:
    lines = [
        "ENTERPRISE QUANTITATIVE RISK CONTEXT:",
        f"- Total Portfolio Financial Value: ₹{context.total_financial_exposure:,.2f}",
        f"- Total Inherent Expected Annual Loss (EAL): ₹{context.total_inherent_eal:,.2f}",
        f"- Total Residual Expected Annual Loss (EAL): ₹{context.total_residual_eal:,.2f}",
        f"- Total Annual Risk Mitigated by Controls: ₹{context.annual_risk_mitigated:,.2f}",
        f"- Overall Portfolio Mitigation Efficiency: {context.overall_mitigation_rate:.2f}%",
        "",
        "TOP RISK-DRIVING ASSETS (Ranked by Residual EAL):",
    ]
    for idx, asset in enumerate(context.top_risk_assets, 1):
        lines.append(
            f"  {idx}. {asset['asset_name']} [Criticality: {asset['criticality_weight']}/5]\n"
            f"     - Financial Asset Value: ₹{asset['financial_value']:,.2f}\n"
            f"     - Residual EAL: ₹{asset['residual_eal']:,.2f} / year (Inherent: ₹{asset['inherent_eal']:,.2f})\n"
            f"     - Active Mitigation Rate: {asset['mitigation_percentage']:.2f}%\n"
            f"     - Key Threat: {asset['top_cve']} (CVSS {asset['cvss_score']})"
        )
    return "\n".join(lines)

def call_gemini_api(system_instruction: str, prompt: str, api_key: str) -> tuple[str, str]:
    model_name = "gemini-2.5-flash"
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=model_name,
            contents=system_instruction + "\n\n" + prompt,
        )
        if response and response.text:
            return response.text, model_name
    except Exception as exc:
        logger.error(f"google-genai client call failed: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Google GenAI API call failed: {str(exc)}"
        )
    
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Google GenAI SDK is not installed."
    )

SYSTEM_INSTRUCTION = """You are the Chief Information Security Officer (CISO) and Quantitative Risk Advisory AI for an enterprise.
Your role is to translate complex technical vulnerabilities (CVEs, CVSS scores), defensive security controls, and quantitative risk metrics (Single Loss Expectancy [SLE], Annualized Rate of Occurrence [ARO], and Expected Annual Loss [EAL / ALE]) into clear, plain-English executive summaries for senior leadership and board members.

Instructions:
1. Always ground your analysis directly in the provided enterprise risk metrics.
2. Clearly identify the highest financial risk drivers (assets with the highest residual Expected Annual Loss).
3. Explain the business and financial impact in dollar amounts, not just technical severity scores.
4. Detail how existing controls (WAF, MFA, EDR) are mitigating exposure and where gaps remain.
5. Provide 2-3 prioritized, actionable recommendations with estimated risk-reduction impact.
6. Maintain an objective, authoritative, executive tone (plain English, structured bullet points, concise)."""


@router.post(
    "/api/ai/query",
    response_model=AIQueryResponse,
    summary="Executive AI Risk Advisory Query",
)
@router.post(
    "/api/ai-advisor",
    response_model=AIQueryResponse,
    include_in_schema=False 
)
async def query_ai_advisor(request: AIQueryRequest) -> AIQueryResponse:
    user_query = request.question.strip() if request.question else ""
    if not user_query:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The 'question' field cannot be empty. Please provide a natural language query."
        )

    api_key = os.getenv("GEMINI_API_KEY")
    context: Optional[RiskContextSummary] = None
    context_str = ""
    if request.include_context:
        try:
            context = gather_risk_context()
            context_str = format_risk_context_for_prompt(context)
        except Exception as exc:
            logger.error(f"Failed to gather risk context: {exc}")
            context_str = "Note: Enterprise quantitative risk context was temporarily unavailable."

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key or not api_key.strip():
        logger.warning("Missing Gemini API key in environment. Using rule-based fallback.")
        return AIQueryResponse(
            question=user_query,
            executive_summary=rule_based_fallback(user_query, context),
            context_used=context,
            model_used="rule-based",
            status="success"
        )

    full_prompt = (
        f"{context_str}\n\n"
        f"EXECUTIVE QUESTION:\n\"{user_query}\"\n\n"
        "Provide an executive summary answering the question with specific reference to our financial exposure, "
        "top risk drivers, control efficacy, and recommended strategic actions."
    )

    try:
        executive_summary, model_used = call_gemini_api(
            system_instruction=SYSTEM_INSTRUCTION,
            prompt=full_prompt,
            api_key=api_key.strip(),
        )
    except Exception as exc:
        logger.error(f"Error during AI advisor inference: {exc}. Using rule-based fallback.")
        return AIQueryResponse(
            question=user_query,
            executive_summary=rule_based_fallback(user_query, context),
            context_used=context,
            model_used="rule-based",
            status="success"
        )

    return AIQueryResponse(
        question=user_query,
        executive_summary=executive_summary,
        context_used=context,
        model_used=model_used,
        status="success",
    )

def rule_based_fallback(query: str, context) -> str:
    lower_q = query.lower()
    
    # 1. Highest financial risk asset
    if "highest" in lower_q and "asset" in lower_q:
        if context and context.top_risk_assets:
            top_asset = context.top_risk_assets[0]
            return f"Our highest financial risk asset is {top_asset['asset_name']} with a residual EAL of ₹{top_asset['residual_eal']:,.2f} (Inherent EAL: ₹{top_asset['inherent_eal']:,.2f}). It is valued at ₹{top_asset['financial_value']:,.2f}."
        return "Asset data is currently unavailable."
        
    # 2. Top vulnerabilities
    elif "vulnerabilities" in lower_q:
        if context and context.top_risk_assets:
            cves = []
            for a in context.top_risk_assets[:3]:
                if a['top_cve'] and a['top_cve'] != "N/A":
                    cves.append(f"{a['top_cve']} on {a['asset_name']} (CVSS {a['cvss_score']}, contributes to ₹{a['residual_eal']:,.2f} EAL)")
            return "The top vulnerabilities contributing to our Expected Annual Loss (EAL) are:\n- " + "\n- ".join(cves)
        return "Vulnerability data is unavailable."

    import sqlite3
    import main
    from app.engines.optimizer import optimize_budget_allocation
    assets, tasks, _ = main.load_seed_data()
    
    conn = sqlite3.connect("rnc_audit.db")
    cursor = conn.cursor()
    cursor.execute("SELECT total_budget FROM audit_logs ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    current_budget = float(row[0]) if row else 2500000.0
    
    valid_tasks = [t for t in tasks if t.risk_reduction > t.cost]
    opt_result = optimize_budget_allocation(budget=current_budget, tasks=valid_tasks, method="exact")
    
    # 3. Best ROSI project
    if "best rosi" in lower_q or "funded project" in lower_q:
        if opt_result.selected_tasks:
            best_task = max(opt_result.selected_tasks, key=lambda t: (t.risk_reduction - t.cost)/t.cost if t.cost > 0 else 0)
            best_rosi = ((best_task.risk_reduction - best_task.cost) / best_task.cost) * 100
            return f"Among the currently funded projects, the best ROSI comes from '{best_task.name}'. It costs ₹{best_task.cost:,.2f} and provides a risk reduction of ₹{best_task.risk_reduction:,.2f}, resulting in a ROSI of {best_rosi:,.2f}%."
        return f"There are no cost-justified funded projects at the current budget of ₹{current_budget:,.2f}."

    # 4. 25% Budget Increase
    elif "25%" in lower_q and "budget" in lower_q:
        new_budget = current_budget * 1.25
        opt_new = optimize_budget_allocation(budget=new_budget, tasks=valid_tasks, method="exact")
        
        diff_tasks = [t for t in opt_new.selected_tasks if t not in opt_result.selected_tasks]
        if diff_tasks:
            names = ", ".join(t.name for t in diff_tasks)
            return f"If the budget is increased by 25% (to ₹{new_budget:,.2f}), we could additionally fund: {names}. This would reduce our total risk exposure further."
        else:
            return f"Increasing the budget by 25% (to ₹{new_budget:,.2f}) would not fund any additional cost-justified projects, as all viable projects are already funded or too expensive."
            
    # Generic fallback
    return "Rule-based advisor: I can currently answer questions about our highest risk assets, top vulnerabilities, best ROSI funded projects, and budget increase scenarios (e.g., 25%)."


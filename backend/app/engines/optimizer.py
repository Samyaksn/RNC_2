"""
Cybersecurity Budget Optimization Engine - Operations Research Knapsack Framework
==================================================================================
Author: Operations Research Engineer
Module: backend.app.engines.optimizer

This module formulates and solves the cybersecurity budget allocation problem as a
0/1 Knapsack optimization model. It maximizes total Expected Annual Loss (EAL) risk
reduction subject to a fixed capital budget constraint (e.g., ₹1 crore / $1M) and computes
comprehensive Return on Security Investment (ROSI) metrics for the optimal portfolio.

Mathematical Formulation:
-------------------------
Given:
    - Fixed Budget: B (where B >= 0)
    - Set of N remediation tasks: T = {t_1, t_2, ..., t_n}
    - Each task t_i has:
        * Implementation Cost: c_i >= 0
        * EAL Risk Reduction (Monetary Benefit): v_i >= 0
    - Binary decision variable: x_i in {0, 1}

Objective:
    Maximize total risk reduction:
        Z = ∑ (v_i * x_i)  for i = 1..N

Subject to Budget Constraint:
        ∑ (c_i * x_i) <= B  for i = 1..N
        x_i in {0, 1}

Return on Security Investment (ROSI):
    ROSI (%) = ((Total EAL Risk Mitigated - Total Implementation Cost) / Total Implementation Cost) * 100%
    Benefit-Cost Ratio (BCR) = Total EAL Risk Mitigated / Total Implementation Cost
    Net Annual Benefit = Total EAL Risk Mitigated - Total Implementation Cost

Dependencies:
    Python standard library only (math, typing, dataclasses, logging).
"""

from __future__ import annotations

import logging
import math
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

logger = logging.getLogger(__name__)


# ============================================================================
# 1. DATA MODELS
# ============================================================================

@dataclass
class RemediationTask:
    """
    Represents a proposed cybersecurity remediation task, patch, or security control project.
    
    Attributes:
        task_id: Unique identifier for the remediation action.
        name: Human-readable title of the project or fix.
        cost: Capital and operational expenditure required (in base currency, e.g. INR / USD).
        risk_reduction: Annual Expected Annual Loss (EAL) reduction achieved if implemented.
        category: Operational domain (e.g. Patching, IAM, Network, Endpoint, Cloud).
        target_asset: Name or identifier of the protected asset.
        cve_id: Associated CVE or weakness identifier (optional).
    """
    task_id: str
    name: str
    cost: float
    risk_reduction: float
    category: str = "General Security"
    target_asset: Optional[str] = None
    cve_id: Optional[str] = None
    compliance_tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.cost, (int, float)):
            raise TypeError(f"Cost must be numeric, got {type(self.cost).__name__}")
        if not isinstance(self.risk_reduction, (int, float)):
            raise TypeError(f"Risk reduction must be numeric, got {type(self.risk_reduction).__name__}")
        
        if math.isnan(self.cost) or math.isinf(self.cost):
            raise ValueError(f"Task '{self.task_id}' cost cannot be NaN or Infinite")
        if math.isnan(self.risk_reduction) or math.isinf(self.risk_reduction):
            raise ValueError(f"Task '{self.task_id}' risk_reduction cannot be NaN or Infinite")

        if self.cost < 0.0:
            raise ValueError(f"Task '{self.task_id}' cost cannot be negative, got {self.cost}")
        if self.risk_reduction < 0.0:
            raise ValueError(f"Task '{self.task_id}' risk_reduction cannot be negative, got {self.risk_reduction}")

    @property
    def efficiency_ratio(self) -> float:
        """Risk reduction per currency unit spent (Bang-for-the-Buck)."""
        if self.cost == 0.0:
            return float("inf") if self.risk_reduction > 0 else 0.0
        return self.risk_reduction / self.cost

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["efficiency_ratio"] = round(self.efficiency_ratio, 4) if not math.isinf(self.efficiency_ratio) else "Infinity"
        return d


@dataclass
class ROSIMetrics:
    """
    Comprehensive financial return and security economic efficiency metrics.
    
    Attributes:
        total_investment_cost: Total monetary expenditure for the selected portfolio.
        total_risk_reduction: Total annual Expected Annual Loss (EAL) prevented.
        net_financial_benefit: Net monetary gain (Risk Reduction - Cost).
        rosi_percentage: Return on Security Investment percentage.
        benefit_cost_ratio: Ratio of annual savings to investment cost (BCR).
        budget_utilization_pct: Percentage of allocated budget utilized.
        remaining_budget: Unallocated surplus budget funds.
    """
    total_investment_cost: float
    total_risk_reduction: float
    net_financial_benefit: float
    rosi_percentage: float
    benefit_cost_ratio: float
    budget_utilization_pct: float
    remaining_budget: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class OptimizationResult:
    """
    Complete solution output for the cybersecurity budget allocation problem.
    
    Attributes:
        allocated_budget: Original available capital budget.
        selected_tasks: Optimal bundle of remediation tasks approved for funding.
        unselected_tasks: Proposed tasks excluded due to budget constraints or lower ROI.
        metrics: Return on Security Investment (ROSI) and budget utilization metrics.
        algorithm_used: Method used to solve the knapsack optimization.
    """
    allocated_budget: float
    selected_tasks: List[RemediationTask]
    unselected_tasks: List[RemediationTask]
    metrics: ROSIMetrics
    algorithm_used: str = "Branch-and-Bound (Exact)"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allocated_budget": self.allocated_budget,
            "selected_count": len(self.selected_tasks),
            "unselected_count": len(self.unselected_tasks),
            "metrics": self.metrics.to_dict(),
            "algorithm_used": self.algorithm_used,
            "selected_tasks": [t.to_dict() for t in self.selected_tasks],
            "unselected_tasks": [t.to_dict() for t in self.unselected_tasks],
        }


# ============================================================================
# 2. RETURN ON SECURITY INVESTMENT (ROSI) FUNCTIONS
# ============================================================================

def calculate_rosi(risk_reduction: float, cost: float) -> float:
    """
    Compute standard Return on Security Investment (ROSI) percentage.
    
    Formula:
        ROSI (%) = ((Risk Reduction - Cost) / Cost) * 100%
        
    Args:
        risk_reduction: Monitized risk reduction (EAL mitigated) >= 0.0.
        cost: Solution implementation expenditure >= 0.0.
        
    Returns:
        ROSI percentage rounded to 2 decimal places.
        If cost is 0.0 and risk_reduction > 0.0, returns 100.0% (positive infinite yield).
        If both are 0.0, returns 0.0%.
    """
    if not isinstance(risk_reduction, (int, float)) or not isinstance(cost, (int, float)):
        raise TypeError("risk_reduction and cost must be numeric")
    if risk_reduction < 0.0 or cost < 0.0:
        raise ValueError("risk_reduction and cost cannot be negative")
    
    if cost == 0.0:
        return 100.0 if risk_reduction > 0.0 else 0.0

    net_benefit = risk_reduction - cost
    rosi_pct = (net_benefit / cost) * 100.0
    return round(float(rosi_pct), 2)


def compute_portfolio_metrics(
    selected_tasks: Sequence[RemediationTask],
    total_budget: float,
) -> ROSIMetrics:
    """
    Compute comprehensive economic, ROSI, and budget utilization metrics for a selected bundle.
    
    Args:
        selected_tasks: Tasks chosen for funding.
        total_budget: Available expenditure ceiling.
        
    Returns:
        ROSIMetrics object containing all financial ratios.
    """
    total_cost = sum(t.cost for t in selected_tasks)
    total_reduction = sum(t.risk_reduction for t in selected_tasks)
    net_benefit = total_reduction - total_cost

    # ROSI calculation with division by zero safeguards
    if total_cost > 0.0:
        rosi_pct = round(((total_reduction - total_cost) / total_cost) * 100.0, 2)
        bcr = round(total_reduction / total_cost, 4)
    else:
        rosi_pct = 100.0 if total_reduction > 0.0 else 0.0
        bcr = float("inf") if total_reduction > 0.0 else 0.0

    # Budget utilization
    remaining = max(0.0, total_budget - total_cost)
    utilization_pct = round((total_cost / total_budget * 100.0), 2) if total_budget > 0.0 else 0.0

    return ROSIMetrics(
        total_investment_cost=round(total_cost, 2),
        total_risk_reduction=round(total_reduction, 2),
        net_financial_benefit=round(net_benefit, 2),
        rosi_percentage=rosi_pct,
        benefit_cost_ratio=bcr if not math.isinf(bcr) else 999.99,
        budget_utilization_pct=utilization_pct,
        remaining_budget=round(remaining, 2),
    )


# ============================================================================
# 3. 0/1 KNAPSACK OPTIMIZATION ALGORITHMS
# ============================================================================

def _knapsack_branch_and_bound_exact(
    budget: float,
    tasks: List[RemediationTask],
) -> List[RemediationTask]:
    """
    Exact Branch-and-Bound solver for 0/1 Knapsack with continuous floating-point weights.
    
    Uses Linear Programming (Fractional Knapsack) relaxation as an admissible upper bound
    to prune non-promising branches, guaranteeing the mathematically exact optimal subset.
    """
    # 1. Filter out free items (cost == 0) - they are always optimal to include if reduction > 0
    always_include: List[RemediationTask] = []
    candidates: List[RemediationTask] = []

    for t in tasks:
        if t.cost == 0.0:
            if t.risk_reduction > 0.0:
                always_include.append(t)
        elif t.cost <= budget:
            candidates.append(t)

    if not candidates:
        return always_include

    # 2. Sort candidate tasks descending by efficiency ratio (risk_reduction / cost)
    candidates.sort(key=lambda t: t.efficiency_ratio, reverse=True)
    n = len(candidates)

    def calculate_upper_bound(index: int, current_weight: float, current_value: float) -> float:
        """Fractional knapsack relaxation upper bound."""
        if current_weight >= budget:
            return 0.0
        
        bound = current_value
        rem_weight = budget - current_weight

        for i in range(index, n):
            task = candidates[i]
            if task.cost <= rem_weight:
                rem_weight -= task.cost
                bound += task.risk_reduction
            else:
                # Take fractional slice of next most efficient item
                bound += task.risk_reduction * (rem_weight / task.cost)
                break
        return bound

    best_value = 0.0
    best_solution_mask: List[bool] = [False] * n
    current_mask: List[bool] = [False] * n

    def search(index: int, current_weight: float, current_value: float) -> None:
        nonlocal best_value, best_solution_mask

        if current_value > best_value:
            best_value = current_value
            best_solution_mask = list(current_mask)

        if index >= n:
            return

        # Check if upper bound can exceed current best solution
        bound = calculate_upper_bound(index, current_weight, current_value)
        if bound <= best_value:
            return

        # Branch 1: INCLUDE candidates[index] (if budget permits)
        task = candidates[index]
        if current_weight + task.cost <= budget + 1e-7:
            current_mask[index] = True
            search(index + 1, current_weight + task.cost, current_value + task.risk_reduction)
            current_mask[index] = False

        # Branch 2: EXCLUDE candidates[index]
        search(index + 1, current_weight, current_value)

    search(0, 0.0, 0.0)

    # Reconstruct optimal item set
    optimal_selected = list(always_include)
    for i in range(n):
        if best_solution_mask[i]:
            optimal_selected.append(candidates[i])

    return optimal_selected


def _knapsack_dynamic_programming(
    budget: float,
    tasks: List[RemediationTask],
    max_grid_size: int = 10000,
) -> List[RemediationTask]:
    """
    Adaptive Scaled Dynamic Programming solver for 0/1 Knapsack.
    
    Dynamically scales currency costs into discrete integer units, capped at max_grid_size
    to ensure O(N * max_grid_size) computational efficiency with exact resolution.
    """
    always_include = [t for t in tasks if t.cost == 0.0 and t.risk_reduction > 0.0]
    candidate_tasks = [t for t in tasks if 0.0 < t.cost <= budget]

    if not candidate_tasks or budget <= 0.0:
        return always_include

    # Determine adaptive scale factor to preserve precision
    min_cost = min(t.cost for t in candidate_tasks)
    scale_factor = max(budget / max_grid_size, min_cost / 100.0)
    if scale_factor <= 0.0:
        scale_factor = 1.0

    int_budget = max(1, min(int(math.floor(budget / scale_factor)), max_grid_size))
    scale_factor = budget / int_budget

    n = len(candidate_tasks)
    weights = [max(1, int(round(t.cost / scale_factor))) for t in candidate_tasks]
    values = [t.risk_reduction for t in candidate_tasks]

    # Initialize DP matrix: (n + 1) x (int_budget + 1)
    dp = [[0.0] * (int_budget + 1) for _ in range(n + 1)]

    for i in range(1, n + 1):
        w = weights[i - 1]
        v = values[i - 1]
        for b in range(int_budget + 1):
            if w <= b:
                dp[i][b] = max(dp[i - 1][b], dp[i - 1][b - w] + v)
            else:
                dp[i][b] = dp[i - 1][b]

    # Backtrack to identify selected items
    selected: List[RemediationTask] = list(always_include)
    b = int_budget
    for i in range(n, 0, -1):
        if dp[i][b] != dp[i - 1][b]:
            selected.append(candidate_tasks[i - 1])
            b -= weights[i - 1]

    # Ensure total real cost doesn't exceed real budget due to discretization rounding
    if sum(t.cost for t in selected) > budget:
        # Prune lowest efficiency item if rounded slightly over
        selected.sort(key=lambda t: t.efficiency_ratio)
        while sum(t.cost for t in selected) > budget and selected:
            selected.pop(0)

    return selected


# ============================================================================
# 4. MAIN OPTIMIZATION ORCHESTRATOR
# ============================================================================

def optimize_budget_allocation(
    budget: float,
    tasks: Sequence[RemediationTask],
    method: str = "exact",
) -> OptimizationResult:
    """
    Optimal cybersecurity budget allocator maximizing quantitative risk reduction (EAL).
    
    Solves the 0/1 Knapsack optimization problem under a hard expenditure ceiling,
    recommends the highest-value security projects, and calculates ROSI metrics.
    
    Args:
        budget: Capital budget limit (>= 0.0, e.g. 10000000 for ₹1 crore).
        tasks: Sequence of RemediationTask candidate proposals.
        method: Optimization algorithm ('exact' for Branch-and-Bound, 'dp' for Dynamic Programming).
        
    Returns:
        OptimizationResult containing the optimal task bundle, unselected items, and ROSI metrics.
        
    Raises:
        TypeError: If budget is non-numeric or tasks is not a sequence.
        ValueError: If budget is negative or method is unrecognized.
    """
    if not isinstance(budget, (int, float)):
        raise TypeError(f"Budget must be numeric, got {type(budget).__name__}")
    if math.isnan(budget) or math.isinf(budget):
        raise ValueError("Budget cannot be NaN or Infinite")
    if budget < 0.0:
        raise ValueError(f"Budget cannot be negative, got {budget}")
    
    if not isinstance(tasks, (list, tuple, set)):
        raise TypeError(f"Tasks must be a sequence of RemediationTask instances, got {type(tasks).__name__}")

    # Validate task instances
    task_list: List[RemediationTask] = []
    for item in tasks:
        if not isinstance(item, RemediationTask):
            raise TypeError(f"All elements must be RemediationTask instances, got {type(item).__name__}")
        task_list.append(item)

    # Handle edge case: zero budget or empty task set
    if budget == 0.0 or not task_list:
        selected: List[RemediationTask] = [t for t in task_list if t.cost == 0.0 and t.risk_reduction > 0.0]
        selected_ids = {t.task_id for t in selected}
        unselected = [t for t in task_list if t.task_id not in selected_ids]
        metrics = compute_portfolio_metrics(selected, budget)
        return OptimizationResult(
            allocated_budget=round(budget, 2),
            selected_tasks=selected,
            unselected_tasks=unselected,
            metrics=metrics,
            algorithm_used="Trivial Zero-Cost Filter",
        )

    # Execute selected knapsack solver
    method_normalized = method.strip().lower()
    if method_normalized in ("exact", "branch_and_bound", "bnb"):
        selected_tasks = _knapsack_branch_and_bound_exact(budget, task_list)
        algo_name = "Branch-and-Bound (0/1 Knapsack Exact)"
    elif method_normalized in ("dp", "dynamic_programming"):
        selected_tasks = _knapsack_dynamic_programming(budget, task_list)
        algo_name = "Scaled Dynamic Programming (0/1 Knapsack)"
    else:
        raise ValueError(f"Unknown optimization method '{method}'. Supported: 'exact', 'dp'")

    # Identify unselected tasks
    selected_ids = {t.task_id for t in selected_tasks}
    unselected_tasks = [t for t in task_list if t.task_id not in selected_ids]

    # Compute financial performance & ROSI metrics
    metrics = compute_portfolio_metrics(selected_tasks, budget)

    # Sort selected tasks descending by efficiency ratio for reporting clarity
    selected_tasks.sort(key=lambda t: t.efficiency_ratio, reverse=True)
    unselected_tasks.sort(key=lambda t: t.efficiency_ratio, reverse=True)

    return OptimizationResult(
        allocated_budget=round(budget, 2),
        selected_tasks=selected_tasks,
        unselected_tasks=unselected_tasks,
        metrics=metrics,
        algorithm_used=algo_name,
    )


# ============================================================================
# 5. CLI & SIMULATION BENCHMARK
# ============================================================================

if __name__ == "__main__":
    print("=================================================================")
    print("  Cybersecurity Budget Optimizer - Knapsack ROSI Allocation      ")
    print("=================================================================")

    # Scenario: ₹1 Crore (INR 10,000,000) Enterprise Security Capital Budget
    BUDGET_INR = 10_000_000.00  # ₹1.00 Crore

    # Candidate security remediation initiatives across enterprise infrastructure
    candidate_initiatives = [
        RemediationTask(
            task_id="TASK-01",
            name="Upgrade Core Banking Database to Patched Version (CVE-2024-3094)",
            cost=2_500_000.00,        # ₹25 Lakhs
            risk_reduction=6_840_000.00, # ₹68.4 Lakhs EAL reduction
            category="Database Security",
            target_asset="Production Core Banking Database",
            cve_id="CVE-2024-3094",
        ),
        RemediationTask(
            task_id="TASK-02",
            name="Deploy Hardware-backed FIDO2 MFA across High-Privilege Accounts",
            cost=1_200_000.00,        # ₹12 Lakhs
            risk_reduction=4_200_000.00, # ₹42.0 Lakhs EAL reduction
            category="Identity & Access Management",
            target_asset="Enterprise IAM / Active Directory",
        ),
        RemediationTask(
            task_id="TASK-03",
            name="Deploy Next-Gen Web Application Firewall for Payment Gateway API",
            cost=3_000_000.00,        # ₹30 Lakhs
            risk_reduction=5_500_000.00, # ₹55.0 Lakhs EAL reduction
            category="Application Security",
            target_asset="Customer Payment Gateway API",
            cve_id="CVE-2024-21413",
        ),
        RemediationTask(
            task_id="TASK-04",
            name="Automated Vulnerability Management & Patch Orchestration Engine",
            cost=1_800_000.00,        # ₹18 Lakhs
            risk_reduction=2_900_000.00, # ₹29.0 Lakhs EAL reduction
            category="SecOps Automation",
            target_asset="Enterprise Fleet (Servers & Workstations)",
        ),
        RemediationTask(
            task_id="TASK-05",
            name="Micro-segmentation & Zero Trust Network Architecture for Core Switches",
            cost=4_500_000.00,        # ₹45 Lakhs
            risk_reduction=4_800_000.00, # ₹48.0 Lakhs EAL reduction
            category="Network Security",
            target_asset="Core Datacenter Network",
        ),
        RemediationTask(
            task_id="TASK-06",
            name="Database Transparent Data Encryption (TDE) & Key Management (HSM)",
            cost=2_000_000.00,        # ₹20 Lakhs
            risk_reduction=3_600_000.00, # ₹36.0 Lakhs EAL reduction
            category="Cryptographic Controls",
            target_asset="Customer Financial Ledger",
        ),
        RemediationTask(
            task_id="TASK-07",
            name="Zero-Cost Hardening: Disable Insecure SSH Ciphers & TLS 1.0/1.1",
            cost=0.00,                # ₹0 (Administrative hardening)
            risk_reduction=850_000.00,   # ₹8.5 Lakhs EAL reduction
            category="Configuration Hardening",
            target_asset="Internet Banking Customer Web Portal",
            cve_id="CVE-2023-48795",
        ),
    ]

    # Execute Optimization
    result = optimize_budget_allocation(budget=BUDGET_INR, tasks=candidate_initiatives, method="exact")

    print(f"\nTarget Budget Allocation   : INR {result.allocated_budget:,.2f} (INR 1.00 Crore)")
    print(f"Optimal Investment Cost    : INR {result.metrics.total_investment_cost:,.2f}")
    print(f"Total EAL Risk Mitigated   : INR {result.metrics.total_risk_reduction:,.2f}")
    print(f"Net Financial Benefit      : INR {result.metrics.net_financial_benefit:,.2f}")
    print(f"Return on Sec. Investment  : {result.metrics.rosi_percentage:.2f}% (ROSI)")
    print(f"Benefit-Cost Ratio (BCR)   : {result.metrics.benefit_cost_ratio:.2f}x")
    print(f"Budget Utilization         : {result.metrics.budget_utilization_pct:.2f}%")
    print(f"Remaining Capital Surplus  : INR {result.metrics.remaining_budget:,.2f}")
    print(f"Algorithm Selected         : {result.algorithm_used}\n")

    print("=================================================================")
    print("  APPROVED REMEDIATION BUNDLE (Maximized Risk Reduction)         ")
    print("=================================================================")
    for idx, task in enumerate(result.selected_tasks, 1):
        print(f"[{idx}] {task.task_id}: {task.name}")
        print(f"    - Cost: INR {task.cost:,.2f} | Risk Mitigated: INR {task.risk_reduction:,.2f} | Bang-for-Buck: {task.efficiency_ratio:.2f}x")
        if task.cve_id:
            print(f"    - Addressed CVE: {task.cve_id} on {task.target_asset}")
    print()

    print("=================================================================")
    print("  DEFERRED REMEDIATION TASKS (Exceeds Current Fiscal Budget)     ")
    print("=================================================================")
    for idx, task in enumerate(result.unselected_tasks, 1):
        print(f"[-] {task.task_id}: {task.name}")
        print(f"    - Cost: INR {task.cost:,.2f} | Risk Mitigated: INR {task.risk_reduction:,.2f} | Bang-for-Buck: {task.efficiency_ratio:.2f}x")
    print()

"""
Quantitative Risk Engine - Expected Annual Loss (EAL) Calculation Framework
============================================================================
Author: Quantitative Risk Engineer
Module: backend.app.engines.risk_engine

This engine provides a mathematically sound, production-grade quantitative cyber risk
assessment framework based on NIST SP 800-30, FAIR (Factor Analysis of Information Risk),
and ISO/IEC 27005 methodologies.

Mathematical Model:
-------------------
1. Exposure Factor (EF):
   - Base Exposure Factor: EF_base = CVSS_Score / 10.0 (bounded in [0.0, 1.0])
   - Security Control Mitigations (Defense-in-Depth Multiplicative Independence):
       Combined Mitigation (M) = 1.0 - ∏ (1.0 - (Effectiveness_i * Coverage_i))
   - Mitigated Exposure Factor: EF_mitigated = EF_base * (1.0 - M)

2. Single Loss Expectancy (SLE):
   - Inherent SLE = Asset Value * EF_base
   - Residual SLE = Asset Value * EF_mitigated

3. Annualized Rate of Occurrence (ARO):
   - Frequency of anticipated security incidents per year derived from CVSS Severity:
     CRITICAL -> 2.50 events/year
     HIGH     -> 1.20 events/year
     MEDIUM   -> 0.40 events/year
     LOW      -> 0.10 events/year
     NONE     -> 0.01 events/year (negligible)

4. Expected Annual Loss (EAL / ALE):
   - Inherent EAL = Inherent SLE * ARO
   - Residual EAL = Residual SLE * ARO
   - Risk Mitigated = Inherent EAL - Residual EAL

Dependencies:
    Python standard library only (math, typing, dataclasses, enum, logging).
"""

from __future__ import annotations

import logging
import math
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Union

logger = logging.getLogger(__name__)


# ============================================================================
# 1. ENUMS & CONSTANTS
# ============================================================================

class SeverityLevel(str, Enum):
    """Vulnerability severity levels aligned with CVSS v3.1 / v4.0 standards."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"

    @classmethod
    def from_string(cls, value: str) -> SeverityLevel:
        """
        Safely parse a string into a SeverityLevel enum member.
        
        Args:
            value: Case-insensitive severity string (e.g. 'high', 'CRITICAL', 'Medium').
            
        Returns:
            SeverityLevel enum member.
            
        Raises:
            ValueError: If the string does not match any valid severity level.
            TypeError: If value is not a string.
        """
        if not isinstance(value, str):
            raise TypeError(f"Severity must be a string, got {type(value).__name__}")
        
        normalized = value.strip().upper()
        try:
            return cls[normalized]
        except KeyError:
            valid_keys = ", ".join(m.value for m in cls)
            raise ValueError(f"Invalid severity '{value}'. Must be one of: {valid_keys}")


# Default Annual Rate of Occurrence (ARO) frequency mappings by severity
# Assumption: Industry standard realistic frequencies for vulnerability exploitation per year.
# A single vulnerability shouldn't mathematically cause multiple total losses per year.
DEFAULT_ARO_MAPPING: Dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 0.50,  # ~1 incident every 2 years
    SeverityLevel.HIGH: 0.25,      # ~1 incident every 4 years
    SeverityLevel.MEDIUM: 0.10,    # ~1 incident every 10 years
    SeverityLevel.LOW: 0.05,       # ~1 incident every 20 years
    SeverityLevel.NONE: 0.01,      # Negligible occurrence rate
}


# ============================================================================
# 2. DATA MODELS
# ============================================================================

@dataclass
class SecurityControl:
    """
    Defensive security safeguard mitigating vulnerability exposure.
    
    Attributes:
        control_id: Unique identifier for the control.
        control_name: Descriptive name of the security control.
        effectiveness_score: Mitigation efficiency between 0.00 (none) and 1.00 (complete).
        coverage_percentage: Scope percentage of control coverage between 0.0 and 100.0.
        is_active: Whether the control is currently active and operational.
    """
    control_id: str
    control_name: str
    effectiveness_score: float
    coverage_percentage: float = 100.0
    is_active: bool = True
    compliance_tags: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.effectiveness_score, (int, float)):
            raise TypeError(f"effectiveness_score must be numeric, got {type(self.effectiveness_score).__name__}")
        if not (0.0 <= self.effectiveness_score <= 1.0):
            raise ValueError(f"effectiveness_score must be within [0.0, 1.0], got {self.effectiveness_score}")
        
        if not isinstance(self.coverage_percentage, (int, float)):
            raise TypeError(f"coverage_percentage must be numeric, got {type(self.coverage_percentage).__name__}")
        if not (0.0 <= self.coverage_percentage <= 100.0):
            raise ValueError(f"coverage_percentage must be within [0.0, 100.0], got {self.coverage_percentage}")


@dataclass
class Vulnerability:
    """
    Security weakness identified on an enterprise asset.
    
    Attributes:
        vuln_id: Unique identifier for the vulnerability record.
        cve_id: Standard CVE identifier or vulnerability code (e.g. CVE-2024-3094).
        cvss_score: Base CVSS score between 0.0 and 10.0.
        severity: Vulnerability severity level (SeverityLevel or string).
        custom_aro: Optional direct override for Annualized Rate of Occurrence.
    """
    vuln_id: str
    cve_id: str
    cvss_score: float
    severity: Union[SeverityLevel, str]
    custom_aro: Optional[float] = None

    def __post_init__(self) -> None:
        if not isinstance(self.cvss_score, (int, float)):
            raise TypeError(f"cvss_score must be numeric, got {type(self.cvss_score).__name__}")
        if not (0.0 <= self.cvss_score <= 10.0):
            raise ValueError(f"cvss_score must be between 0.0 and 10.0, got {self.cvss_score}")
        
        if isinstance(self.severity, str):
            self.severity = SeverityLevel.from_string(self.severity)
        elif not isinstance(self.severity, SeverityLevel):
            raise TypeError(f"severity must be SeverityLevel or str, got {type(self.severity).__name__}")

        if self.custom_aro is not None:
            if not isinstance(self.custom_aro, (int, float)):
                raise TypeError(f"custom_aro must be numeric, got {type(self.custom_aro).__name__}")
            if self.custom_aro < 0.0:
                raise ValueError(f"custom_aro cannot be negative, got {self.custom_aro}")


@dataclass
class Asset:
    """
    Physical, logical, or data asset tracked in the risk register.
    
    Attributes:
        asset_id: Unique asset identifier.
        name: Asset name or hostname.
        financial_value: Replacement / impact valuation of the asset (>= 0.00).
        criticality_weight: Business criticality weight ranking from 1 (lowest) to 5 (mission critical).
        vulnerabilities: List of identified vulnerabilities associated with this asset.
        controls: List of security controls defending this asset.
    """
    asset_id: str
    name: str
    financial_value: float
    criticality_weight: int = 3
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    controls: List[SecurityControl] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isinstance(self.financial_value, (int, float)):
            raise TypeError(f"financial_value must be numeric, got {type(self.financial_value).__name__}")
        if self.financial_value < 0.0:
            raise ValueError(f"financial_value cannot be negative, got {self.financial_value}")
        
        if not isinstance(self.criticality_weight, int):
            raise TypeError(f"criticality_weight must be an integer, got {type(self.criticality_weight).__name__}")
        if not (1 <= self.criticality_weight <= 5):
            raise ValueError(f"criticality_weight must be between 1 and 5, got {self.criticality_weight}")


# ============================================================================
# 3. RESULT DATA MODELS
# ============================================================================

@dataclass
class VulnerabilityRiskResult:
    """Detailed risk metrics for an individual vulnerability."""
    vuln_id: str
    cve_id: str
    cvss_score: float
    severity: str
    base_exposure_factor: float
    mitigated_exposure_factor: float
    inherent_sle: float
    residual_sle: float
    aro: float
    inherent_eal: float
    residual_eal: float
    risk_reduction_eal: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AssetRiskResult:
    """Consolidated risk metrics for an asset across all its vulnerabilities and controls."""
    asset_id: str
    asset_name: str
    financial_value: float
    criticality_weight: int
    vulnerability_count: int
    active_controls_count: int
    aggregate_mitigation_score: float
    total_inherent_sle: float
    total_residual_sle: float
    total_inherent_eal: float
    total_residual_eal: float
    total_risk_mitigated_eal: float
    risk_mitigation_percentage: float
    vulnerability_details: List[VulnerabilityRiskResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EnterpriseRiskSummary:
    """Enterprise-wide portfolio aggregation of financial asset exposure and risk metrics."""
    total_assets: int
    total_financial_value: float
    total_vulnerabilities: int
    total_inherent_eal: float
    total_residual_eal: float
    total_annual_risk_mitigated: float
    overall_mitigation_percentage: float
    average_criticality_weight: float
    asset_risks: List[AssetRiskResult] = field(default_factory=list)
    top_risk_assets: List[AssetRiskResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ============================================================================
# 4. CORE MATHEMATICAL CALCULATION FUNCTIONS
# ============================================================================

def calculate_base_exposure_factor(cvss_score: float) -> float:
    """
    Calculate the base Exposure Factor (EF) directly from a CVSS score.
    
    Formula:
        EF_base = CVSS / 10.0
        
    Args:
        cvss_score: CVSS score between 0.0 and 10.0.
        
    Returns:
        Exposure factor bounded within [0.0, 1.0].
        
    Raises:
        TypeError: If cvss_score is not numeric.
        ValueError: If cvss_score is not in range [0.0, 10.0].
    """
    if not isinstance(cvss_score, (int, float)):
        raise TypeError(f"cvss_score must be a number, got {type(cvss_score).__name__}")
    if math.isnan(cvss_score) or math.isinf(cvss_score):
        raise ValueError("cvss_score cannot be NaN or Infinite")
    if not (0.0 <= cvss_score <= 10.0):
        raise ValueError(f"cvss_score must be between 0.0 and 10.0, got {cvss_score}")
    
    return float(cvss_score / 10.0)


def calculate_combined_control_effectiveness(
    controls: Optional[Sequence[SecurityControl]],
) -> float:
    """
    Calculate the aggregate mitigation effectiveness of multiple defense-in-depth controls.
    
    Model:
        Multiplicative independent safeguard failure model:
        Each active control i provides mitigation: m_i = Effectiveness_i * (Coverage_i / 100.0)
        Residual unmitigated fraction = ∏ (1.0 - m_i)
        Combined Mitigation Score (M) = 1.0 - ∏ (1.0 - m_i)
        
    Args:
        controls: Sequence of SecurityControl objects (or None/empty).
        
    Returns:
        Combined effectiveness score bounded within [0.0, 1.0].
    """
    if not controls:
        return 0.0

    unmitigated_ratio = 1.0
    for control in controls:
        if not isinstance(control, SecurityControl):
            raise TypeError(f"Expected SecurityControl instance, got {type(control).__name__}")
        
        if not control.is_active:
            continue
        
        # Effective mitigation considering both effectiveness score and coverage percentage
        effective_coverage = control.coverage_percentage / 100.0
        single_control_mitigation = control.effectiveness_score * effective_coverage
        
        # Clamp to [0.0, 1.0] for safety
        single_control_mitigation = max(0.0, min(1.0, single_control_mitigation))
        unmitigated_ratio *= (1.0 - single_control_mitigation)

    combined_effectiveness = 1.0 - unmitigated_ratio
    return max(0.0, min(1.0, float(combined_effectiveness)))


def calculate_mitigated_exposure_factor(
    cvss_score: float,
    controls: Optional[Sequence[SecurityControl]] = None,
) -> float:
    """
    Calculate the mitigated Exposure Factor incorporating CVSS score and active security controls.
    
    Formula:
        EF_base = cvss_score / 10.0
        Combined_Mitigation = calculate_combined_control_effectiveness(controls)
        EF_mitigated = EF_base * (1.0 - Combined_Mitigation)
        
    Args:
        cvss_score: Base CVSS score [0.0, 10.0].
        controls: Optional list of applied security controls.
        
    Returns:
        Mitigated exposure factor bounded in [0.0, 1.0].
    """
    base_ef = calculate_base_exposure_factor(cvss_score)
    combined_mitigation = calculate_combined_control_effectiveness(controls)
    mitigated_ef = base_ef * (1.0 - combined_mitigation)
    return max(0.0, min(1.0, float(mitigated_ef)))


def calculate_single_loss_expectancy(
    asset_value: float,
    exposure_factor: float,
) -> float:
    """
    Calculate Single Loss Expectancy (SLE).
    
    Formula:
        SLE = Asset Value * Exposure Factor
        
    Args:
        asset_value: Financial valuation of the asset (>= 0.00).
        exposure_factor: Exposure factor percentage [0.0, 1.0].
        
    Returns:
        Monetary Single Loss Expectancy rounded to 2 decimal places.
        
    Raises:
        TypeError: If arguments are non-numeric.
        ValueError: If asset_value is negative or exposure_factor is out of [0.0, 1.0].
    """
    if not isinstance(asset_value, (int, float)):
        raise TypeError(f"asset_value must be numeric, got {type(asset_value).__name__}")
    if not isinstance(exposure_factor, (int, float)):
        raise TypeError(f"exposure_factor must be numeric, got {type(exposure_factor).__name__}")
    
    if math.isnan(asset_value) or math.isinf(asset_value):
        raise ValueError("asset_value cannot be NaN or Infinite")
    if math.isnan(exposure_factor) or math.isinf(exposure_factor):
        raise ValueError("exposure_factor cannot be NaN or Infinite")
        
    if asset_value < 0.0:
        raise ValueError(f"asset_value cannot be negative, got {asset_value}")
    if not (0.0 <= exposure_factor <= 1.0):
        raise ValueError(f"exposure_factor must be within [0.0, 1.0], got {exposure_factor}")

    sle = asset_value * exposure_factor
    return round(float(sle), 2)


# Concise alias for Single Loss Expectancy
calculate_sle = calculate_single_loss_expectancy


def calculate_annualized_rate_of_occurrence(
    severity: Union[SeverityLevel, str],
    custom_mapping: Optional[Dict[Union[SeverityLevel, str], float]] = None,
) -> float:
    """
    Calculate the Annualized Rate of Occurrence (ARO) based on vulnerability severity.
    
    Args:
        severity: Severity level (SeverityLevel enum or string: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE').
        custom_mapping: Optional dictionary overriding default annual occurrence frequencies.
        
    Returns:
        Estimated annualized occurrence rate (events per year).
        
    Raises:
        TypeError: If severity or mapping values are not the expected types.
        ValueError: If severity is unrecognized or mapped ARO is negative.
    """
    if isinstance(severity, str):
        severity_enum = SeverityLevel.from_string(severity)
    elif isinstance(severity, SeverityLevel):
        severity_enum = severity
    else:
        raise TypeError(f"severity must be SeverityLevel or str, got {type(severity).__name__}")

    # Check custom mapping first if provided
    if custom_mapping:
        for k, v in custom_mapping.items():
            k_enum = k if isinstance(k, SeverityLevel) else SeverityLevel.from_string(str(k))
            if k_enum == severity_enum:
                if not isinstance(v, (int, float)):
                    raise TypeError(f"Mapped ARO value must be numeric, got {type(v).__name__}")
                if v < 0.0:
                    raise ValueError(f"Mapped ARO value cannot be negative, got {v}")
                return float(v)

    aro = DEFAULT_ARO_MAPPING[severity_enum]
    return float(aro)


# Concise alias for Annualized Rate of Occurrence
calculate_aro = calculate_annualized_rate_of_occurrence


def calculate_expected_annual_loss(
    sle: float,
    aro: float,
) -> float:
    """
    Compute Expected Annual Loss (EAL / ALE).
    
    Formula:
        EAL = SLE * ARO
        
    Args:
        sle: Single Loss Expectancy (>= 0.00).
        aro: Annualized Rate of Occurrence (>= 0.00).
        
    Returns:
        Expected Annual Loss rounded to 2 decimal places.
        
    Raises:
        TypeError: If arguments are non-numeric.
        ValueError: If sle or aro is negative, NaN, or Infinite.
    """
    if not isinstance(sle, (int, float)):
        raise TypeError(f"sle must be numeric, got {type(sle).__name__}")
    if not isinstance(aro, (int, float)):
        raise TypeError(f"aro must be numeric, got {type(aro).__name__}")
    
    if math.isnan(sle) or math.isinf(sle):
        raise ValueError("sle cannot be NaN or Infinite")
    if math.isnan(aro) or math.isinf(aro):
        raise ValueError("aro cannot be NaN or Infinite")

    if sle < 0.0:
        raise ValueError(f"sle cannot be negative, got {sle}")
    if aro < 0.0:
        raise ValueError(f"aro cannot be negative, got {aro}")

    eal = sle * aro
    return round(float(eal), 2)


# Concise alias for Expected Annual Loss
calculate_eal = calculate_expected_annual_loss


# ============================================================================
# 5. ASSET-LEVEL RISK ASSESSMENT
# ============================================================================

def calculate_asset_risk(
    asset: Asset,
    custom_aro_mapping: Optional[Dict[Union[SeverityLevel, str], float]] = None,
) -> AssetRiskResult:
    """
    Compute comprehensive quantitative risk metrics for an individual asset.
    
    Evaluates:
        - Inherent and residual SLE for each vulnerability.
        - Inherent and residual EAL for each vulnerability based on ARO.
        - Total asset inherent vs residual EAL roll-up.
        - Overall mitigation benefit ($ savings) and mitigation percentage.
        
    Args:
        asset: The Asset entity under assessment.
        custom_aro_mapping: Optional custom ARO frequency dictionary.
        
    Returns:
        AssetRiskResult dataclass containing granular vulnerability breakdown
        and rolled-up asset totals.
        
    Raises:
        TypeError: If asset is not an Asset instance.
    """
    if not isinstance(asset, Asset):
        raise TypeError(f"Expected Asset instance, got {type(asset).__name__}")

    active_controls = [c for c in asset.controls if c.is_active]
    combined_effectiveness = calculate_combined_control_effectiveness(active_controls)

    vuln_results: List[VulnerabilityRiskResult] = []
    total_inherent_sle = 0.0
    total_residual_sle = 0.0
    total_inherent_eal = 0.0
    total_residual_eal = 0.0

    for vuln in asset.vulnerabilities:
        # 1. Base Exposure Factor
        base_ef = calculate_base_exposure_factor(vuln.cvss_score)
        
        # 2. Mitigated Exposure Factor
        mitigated_ef = max(0.0, min(1.0, base_ef * (1.0 - combined_effectiveness)))
        
        # 3. SLE Calculations
        inherent_sle = calculate_sle(asset.financial_value, base_ef)
        residual_sle = calculate_sle(asset.financial_value, mitigated_ef)
        
        # 4. ARO Determination
        if vuln.custom_aro is not None:
            aro = float(vuln.custom_aro)
        else:
            aro = calculate_aro(vuln.severity, custom_mapping=custom_aro_mapping)
            
        # 5. EAL Calculations
        inherent_eal = calculate_eal(inherent_sle, aro)
        residual_eal = calculate_eal(residual_sle, aro)
        risk_reduction = round(max(0.0, inherent_eal - residual_eal), 2)
        
        vuln_results.append(
            VulnerabilityRiskResult(
                vuln_id=vuln.vuln_id,
                cve_id=vuln.cve_id,
                cvss_score=vuln.cvss_score,
                severity=vuln.severity.value if isinstance(vuln.severity, SeverityLevel) else str(vuln.severity),
                base_exposure_factor=round(base_ef, 4),
                mitigated_exposure_factor=round(mitigated_ef, 4),
                inherent_sle=inherent_sle,
                residual_sle=residual_sle,
                aro=round(aro, 4),
                inherent_eal=inherent_eal,
                residual_eal=residual_eal,
                risk_reduction_eal=risk_reduction,
            )
        )
        
        total_inherent_sle += inherent_sle
        total_residual_sle += residual_sle
        total_inherent_eal += inherent_eal
        total_residual_eal += residual_eal

    total_inherent_sle = round(total_inherent_sle, 2)
    total_residual_sle = round(total_residual_sle, 2)
    
    # Cap EAL so it never exceeds the asset's financial value
    total_inherent_eal = round(min(total_inherent_eal, asset.financial_value), 2)
    total_residual_eal = round(min(total_residual_eal, asset.financial_value), 2)
    
    total_mitigated_eal = round(max(0.0, total_inherent_eal - total_residual_eal), 2)

    # Safe division for mitigation percentage calculation
    if total_inherent_eal > 0.0:
        mitigation_pct = round((total_mitigated_eal / total_inherent_eal) * 100.0, 2)
    else:
        mitigation_pct = 100.0 if not asset.vulnerabilities else 0.0

    return AssetRiskResult(
        asset_id=asset.asset_id,
        asset_name=asset.name,
        financial_value=asset.financial_value,
        criticality_weight=asset.criticality_weight,
        vulnerability_count=len(asset.vulnerabilities),
        active_controls_count=len(active_controls),
        aggregate_mitigation_score=round(combined_effectiveness, 4),
        total_inherent_sle=total_inherent_sle,
        total_residual_sle=total_residual_sle,
        total_inherent_eal=total_inherent_eal,
        total_residual_eal=total_residual_eal,
        total_risk_mitigated_eal=total_mitigated_eal,
        risk_mitigation_percentage=mitigation_pct,
        vulnerability_details=vuln_results,
    )


# Alias for calculate_asset_risk
calculate_asset_eal = calculate_asset_risk


# ============================================================================
# 6. ENTERPRISE-LEVEL RISK AGGREGATION
# ============================================================================

def calculate_enterprise_risk(
    assets: Sequence[Asset],
    custom_aro_mapping: Optional[Dict[Union[SeverityLevel, str], float]] = None,
    top_n_critical: int = 5,
) -> EnterpriseRiskSummary:
    """
    Compute aggregate portfolio quantitative risk metrics across all enterprise assets.
    
    Aggregates:
        - Total asset financial valuation.
        - Total portfolio inherent and residual EAL.
        - Total annual risk mitigated by existing controls.
        - Overall enterprise mitigation percentage.
        - Top N most critical assets ranked by residual EAL.
        
    Args:
        assets: Sequence of Asset instances representing enterprise inventory.
        custom_aro_mapping: Optional custom ARO frequency mapping.
        top_n_critical: Number of top risk assets to isolate for executive reporting.
        
    Returns:
        EnterpriseRiskSummary with portfolio roll-ups and ranked asset reports.
        
    Raises:
        TypeError: If assets is not a valid sequence or top_n_critical is invalid.
    """
    if not isinstance(assets, (list, tuple, set)):
        raise TypeError(f"assets must be a sequence of Asset objects, got {type(assets).__name__}")
    if not isinstance(top_n_critical, int) or top_n_critical < 0:
        raise ValueError(f"top_n_critical must be a non-negative integer, got {top_n_critical}")

    if not assets:
        return EnterpriseRiskSummary(
            total_assets=0,
            total_financial_value=0.00,
            total_vulnerabilities=0,
            total_inherent_eal=0.00,
            total_residual_eal=0.00,
            total_annual_risk_mitigated=0.00,
            overall_mitigation_percentage=0.00,
            average_criticality_weight=0.00,
            asset_risks=[],
            top_risk_assets=[],
        )

    asset_reports: List[AssetRiskResult] = []
    total_financial_value = 0.0
    total_vulns = 0
    total_inherent_eal = 0.0
    total_residual_eal = 0.0
    criticality_sum = 0

    for asset in assets:
        report = calculate_asset_risk(asset, custom_aro_mapping=custom_aro_mapping)
        asset_reports.append(report)
        
        total_financial_value += asset.financial_value
        total_vulns += report.vulnerability_count
        total_inherent_eal += report.total_inherent_eal
        total_residual_eal += report.total_residual_eal
        criticality_sum += asset.criticality_weight

    total_financial_value = round(total_financial_value, 2)
    total_inherent_eal = round(total_inherent_eal, 2)
    total_residual_eal = round(total_residual_eal, 2)
    total_risk_mitigated = round(max(0.0, total_inherent_eal - total_residual_eal), 2)
    
    # Safe division for enterprise overall mitigation percentage
    if total_inherent_eal > 0.0:
        overall_mitigation_pct = round((total_risk_mitigated / total_inherent_eal) * 100.0, 2)
    else:
        overall_mitigation_pct = 100.0 if not total_vulns else 0.0

    avg_criticality = round(criticality_sum / len(assets), 2)

    # Rank assets by residual EAL descending (top risk drivers)
    ranked_assets = sorted(asset_reports, key=lambda a: a.total_residual_eal, reverse=True)
    top_assets = ranked_assets[:top_n_critical]

    return EnterpriseRiskSummary(
        total_assets=len(assets),
        total_financial_value=total_financial_value,
        total_vulnerabilities=total_vulns,
        total_inherent_eal=total_inherent_eal,
        total_residual_eal=total_residual_eal,
        total_annual_risk_mitigated=total_risk_mitigated,
        overall_mitigation_percentage=overall_mitigation_pct,
        average_criticality_weight=avg_criticality,
        asset_risks=asset_reports,
        top_risk_assets=top_assets,
    )


import random
import statistics

def simulate_monte_carlo_risk(
    assets: Sequence[Asset],
    iterations: int = 10000,
    custom_aro_mapping: Optional[Dict[Union[SeverityLevel, str], float]] = None
) -> Dict[str, float]:
    """
    Performs a Monte Carlo simulation to generate a probabilistic distribution of Expected Annual Loss (EAL).
    Varies the ARO and Exposure Factor using a triangular/normal distribution.
    
    Returns:
        Dictionary containing p50, p90, p95, and mean loss ranges.
    """
    results = []
    
    # Baseline calculations
    for _ in range(iterations):
        iter_loss = 0.0
        for asset in assets:
            asset_loss = 0.0
            
            # Combine control effectiveness (as done in calculate_asset_risk)
            combined_mitigation = 0.0
            active_controls = [c for c in asset.controls if c.is_active]
            if active_controls:
                residual_multiplier = 1.0
                for c in active_controls:
                    residual_multiplier *= (1.0 - (c.effectiveness_score * (c.coverage_percentage / 100.0)))
                combined_mitigation = 1.0 - residual_multiplier
            
            for vuln in asset.vulnerabilities:
                # Stochastic ARO: vary between 50% and 150% of the baseline
                baseline_aro = 0.0
                if custom_aro_mapping and vuln.severity in custom_aro_mapping:
                    baseline_aro = custom_aro_mapping[vuln.severity]
                elif vuln.severity.value in DEFAULT_ARO_MAPPING:
                    baseline_aro = DEFAULT_ARO_MAPPING[vuln.severity.value]
                else:
                    baseline_aro = 0.1
                
                # Sample ARO (Triangular distribution: min=0.5*baseline, mode=baseline, max=1.5*baseline)
                simulated_aro = random.triangular(baseline_aro * 0.5, baseline_aro * 1.5, baseline_aro)
                
                # Stochastic Exposure Factor (CVSS / 10.0, varying slightly)
                base_ef = vuln.cvss_score / 10.0
                simulated_ef = random.triangular(max(0.01, base_ef * 0.8), min(1.0, base_ef * 1.2), base_ef)
                
                # Apply mitigation
                mitigated_ef = simulated_ef * (1.0 - combined_mitigation)
                
                # Calculate SLE and EAL for this iteration
                sle = asset.financial_value * mitigated_ef
                eal = sle * simulated_aro
                asset_loss += eal
                
            # Cap EAL so it never exceeds the asset's financial value
            asset_loss = min(asset_loss, asset.financial_value)
            
            iter_loss += asset_loss
        results.append(iter_loss)
        
    results.sort()
    
    return {
        "mean_loss": round(statistics.mean(results), 2),
        "p50_loss": round(results[int(iterations * 0.50)], 2),
        "p90_loss": round(results[int(iterations * 0.90)], 2),
        "p95_loss": round(results[int(iterations * 0.95)], 2),
    }

# ============================================================================
# 7. CLI / SMOKE TEST EXECUTION
# ============================================================================

if __name__ == "__main__":
    import json

    print("=================================================================")
    print("  Quantitative Risk Engine - Expected Annual Loss (EAL) Test Run ")
    print("=================================================================")

    # Define Sample Security Controls
    waf = SecurityControl(
        control_id="ctrl-01",
        control_name="Web Application Firewall (WAF)",
        effectiveness_score=0.85,
        coverage_percentage=100.0,
    )
    mfa = SecurityControl(
        control_id="ctrl-02",
        control_name="FIDO2 Multi-Factor Authentication",
        effectiveness_score=0.90,
        coverage_percentage=95.0,
    )
    edr = SecurityControl(
        control_id="ctrl-03",
        control_name="Endpoint Detection & Response (EDR)",
        effectiveness_score=0.75,
        coverage_percentage=100.0,
    )

    # Define Sample Assets with Vulnerabilities
    core_banking_db = Asset(
        asset_id="ast-01",
        name="Production Core Banking Database",
        financial_value=5_000_000.00,
        criticality_weight=5,
        vulnerabilities=[
            Vulnerability(
                vuln_id="v-01",
                cve_id="CVE-2024-3094",
                cvss_score=10.0,
                severity=SeverityLevel.CRITICAL,
            ),
            Vulnerability(
                vuln_id="v-02",
                cve_id="CVE-2023-48795",
                cvss_score=5.9,
                severity=SeverityLevel.MEDIUM,
            ),
        ],
        controls=[waf, mfa],
    )

    customer_portal = Asset(
        asset_id="ast-02",
        name="Internet Banking Customer Web Portal",
        financial_value=1_500_000.00,
        criticality_weight=4,
        vulnerabilities=[
            Vulnerability(
                vuln_id="v-03",
                cve_id="CVE-2023-38606",
                cvss_score=7.8,
                severity=SeverityLevel.HIGH,
            ),
        ],
        controls=[waf, edr],
    )

    # Calculate Enterprise Risk
    enterprise_summary = calculate_enterprise_risk([core_banking_db, customer_portal])

    print(f"\nTotal Enterprise Valuation : ${enterprise_summary.total_financial_value:,.2f}")
    print(f"Total Inherent EAL         : ${enterprise_summary.total_inherent_eal:,.2f}")
    print(f"Total Residual EAL         : ${enterprise_summary.total_residual_eal:,.2f}")
    print(f"Annual Risk Mitigated      : ${enterprise_summary.total_annual_risk_mitigated:,.2f}")
    print(f"Overall Mitigation Rate    : {enterprise_summary.overall_mitigation_percentage:.2f}%\n")

    for asset_risk in enterprise_summary.top_risk_assets:
        print(f"[*] Asset: {asset_risk.asset_name} (Criticality: {asset_risk.criticality_weight})")
        print(f"    - Financial Value : ${asset_risk.financial_value:,.2f}")
        print(f"    - Inherent EAL    : ${asset_risk.total_inherent_eal:,.2f}")
        print(f"    - Residual EAL    : ${asset_risk.total_residual_eal:,.2f}")
        print(f"    - Mitigation      : {asset_risk.risk_mitigation_percentage:.2f}%")
        for v in asset_risk.vulnerability_details:
            print(f"      > [{v.severity}] {v.cve_id} (CVSS: {v.cvss_score}) | SLE: ${v.residual_sle:,.2f} | ARO: {v.aro} | EAL: ${v.residual_eal:,.2f}")
        print()

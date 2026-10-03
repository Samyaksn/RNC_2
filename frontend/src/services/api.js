const API_BASE_URL = 'http://127.0.0.1:8000';

export async function fetchRootStatus() {
  try {
    const res = await fetch(`${API_BASE_URL}/`);
    return await res.json();
  } catch (error) {
    console.error("Backend status check failed:", error);
    return { status: "offline" };
  }
}

export async function runRiskSimulation(budgets) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/optimize`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(budgets),
    });
    return await response.json();
  } catch (error) {
    console.error("Simulation error:", error);
    return {};
  }
}

export async function fetchAuditLogs() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/audits`);
    const data = await response.json();
    return data.logs || [];
  } catch (error) {
    console.error("Failed to fetch audit logs:", error);
    return [];
  }
}

export async function consultAIAdvisor(query) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/ai/query`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: query }),
    });
    const data = await response.json();
    return data.executive_summary || "AI Engine currently bypassed.";
  } catch (error) {
    return "AI Engine currently bypassed.";
  }
}

export async function downloadExecutiveReport() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/export-report`);
    const textData = await response.text();
    
    // Create a downloadable blob link
    const blob = new Blob([textData], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `RNC_Executive_Briefing_${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  } catch (error) {
    console.error("Failed to download executive report:", error);
  }
}

export async function getAssets() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/assets`);
    const data = await response.json();
    return data.assets || [];
  } catch (error) {
    console.error("Failed to fetch assets:", error);
    return [];
  }
}

export async function updateAssets(updates) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/assets`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });
    if (!response.ok) {
      const err = await response.json();
      return { status: "error", detail: err.detail };
    }
    return await response.json();
  } catch (error) {
    console.error("Failed to update assets:", error);
    return { status: "error", detail: error.message };
  }
}

export async function resetAssets() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/assets/reset`, {
      method: 'POST',
    });
    return await response.json();
  } catch (error) {
    console.error("Failed to reset assets:", error);
    return { status: "error" };
  }
}
export async function fetchBaseline() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/baseline`);
    return await response.json();
  } catch (error) {
    console.error("Failed to fetch baseline:", error);
    return { status: "error" };
  }
}

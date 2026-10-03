import React, { useState, useEffect } from 'react';
import { ShieldAlert, TrendingDown, Lock, Activity, RefreshCw, Layers, History, Download, Target, Database } from 'lucide-react';
import { fetchRootStatus, runRiskSimulation, fetchAuditLogs, downloadExecutiveReport, consultAIAdvisor, getAssets, updateAssets, resetAssets, fetchBaseline } from '../services/api';

export default function Dashboard() {
  const [riskExposure, setRiskExposure] = useState(0);
  const [optimizationIndex, setOptimizationIndex] = useState("Uncalculated");
  const [selectedTasks, setSelectedTasks] = useState([]);
  const [monteCarlo, setMonteCarlo] = useState(null);
  const [simulationMessage, setSimulationMessage] = useState("");
  const [budgetData, setBudgetData] = useState(null);
  const [baselineData, setBaselineData] = useState(null);
  
  // Single Budget Input
  const [totalBudget, setTotalBudget] = useState(2500000);

  const [backendStatus, setBackendStatus] = useState('Checking...');
  const [auditLogs, setAuditLogs] = useState([]);
  const [aiQuery, setAiQuery] = useState('');
  const [aiResponse, setAiResponse] = useState('AI Advisor is currently in standby mode.');
  const [loading, setLoading] = useState(false);
  const [assets, setAssets] = useState([]);
  const [showAssets, setShowAssets] = useState(false);

  const loadAuditsAndAssets = async () => {
    const logs = await fetchAuditLogs();
    setAuditLogs(logs);
    const fetchedAssets = await getAssets();
    setAssets(fetchedAssets);
  };

  const reloadBaseline = async () => {
    const data = await fetchBaseline();
    if (data.riskExposure) {
      setRiskExposure(data.riskExposure);
      setMonteCarlo(data.monte_carlo);
      setOptimizationIndex("Uncalculated");
      setSelectedTasks([]);
      setSimulationMessage("");
      setBudgetData(null);
    }
  };

  useEffect(() => {
    fetchRootStatus().then(data => {
      setBackendStatus(data.status === 'online' ? 'Connected' : 'Offline');
    });
    loadAuditsAndAssets();
    reloadBaseline();
  }, []);

  const handleSimulate = async () => {
    const payload = {
      ransomwareBudget: totalBudget,
      cloudBudget: 0,
      supplyChainBudget: 0
    };
    const result = await runRiskSimulation(payload);
    if (result.riskExposure !== undefined) {
      setRiskExposure(result.riskExposure);
      setOptimizationIndex(result.optimizationIndex);
      setSelectedTasks(result.selected_tasks || []);
      setMonteCarlo(result.monte_carlo || null);
      setSimulationMessage(result.message || "");
      if (result.budget !== undefined) {
        setBudgetData({ budget: result.budget, allocated: result.allocated, unspent: result.unspent });
      }
      // Refresh audit logs table immediately after calculation
      loadAuditsAndAssets();
    }
  };

  const handleAskAI = async (e) => {
    e.preventDefault();
    if (!aiQuery.trim()) return;
    setLoading(true);
    const responseText = await consultAIAdvisor(aiQuery);
    setAiResponse(responseText);
    setLoading(false);
  };

  const handleChipClick = async (q) => {
    setAiQuery(q);
    setLoading(true);
    const responseText = await consultAIAdvisor(q);
    setAiResponse(responseText);
    setLoading(false);
  };

  const suggestedQuestions = [
    "What is our highest financial risk asset?",
    "What are the top vulnerabilities?",
    "Which funded project gives the best ROSI?",
    "What happens if the budget is increased by 25%?"
  ];

  const handleAssetChange = (assetId, newValue) => {
    setAssets(assets.map(a => 
      a.asset_id === assetId ? { ...a, financial_value: Number(newValue) } : a
    ));
  };

  const handleSaveAssets = async () => {
    const updates = assets.map(a => ({ asset_id: a.asset_id, financial_value: Number(a.financial_value) }));
    const result = await updateAssets(updates);
    if (result.status === "error") {
      const msg = Array.isArray(result.detail) ? result.detail[0].msg : result.detail;
      alert("Validation Error: " + msg);
    } else {
      alert("Asset valuations saved successfully. Recalculate to see updated exposure.");
      reloadBaseline();
    }
  };

  const formatIndianCurrency = (val) => {
    const num = Number(val);
    if (isNaN(num)) return "0";
    if (num >= 10000000) return (num / 10000000).toFixed(2) + ' Cr';
    if (num >= 100000) return (num / 100000).toFixed(2) + ' L';
    return num.toLocaleString('en-IN');
  };

  const handleResetAssets = async () => {
    await resetAssets();
    await loadAuditsAndAssets();
    reloadBaseline();
    alert("Assets reset to default original valuations.");
  };

  return (
    <div className="min-h-screen bg-[#0B0F19] text-slate-100 p-6 font-sans">
      {/* Top Navigation Bar */}
      <header className="flex justify-between items-center border-b border-[#1F2937] pb-4 mb-8">
        <div className="flex items-center space-x-3">
          <div className="bg-cyan-500/15 border border-cyan-500/30 p-2.5 rounded-xl">
            <ShieldAlert className="w-7 h-7 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-2xl font-black tracking-wider bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Relegate and Celebrate <span className="text-slate-300 text-sm font-normal tracking-normal ml-2">| Cyber Risk Optimization</span>
            </h1>
            <p className="text-xs text-slate-400">Continuous Risk Quantification & Knapsack Budget Optimization</p>
          </div>
        </div>
        <div className="flex items-center space-x-4">
          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-indigo-500/10 text-indigo-400 border border-indigo-500/20 shadow-[0_0_10px_rgba(99,102,241,0.2)]">
            <span className="w-2 h-2 rounded-full bg-indigo-400 mr-2"></span>
            Blockchain: Secured
          </span>
          <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <span className="w-2 h-2 rounded-full bg-emerald-400 mr-2 animate-pulse"></span>
            Backend: {backendStatus}
          </span>
          <button 
            onClick={downloadExecutiveReport}
            className="flex items-center bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-cyan-500/30 px-3.5 py-2 rounded-xl text-xs font-semibold transition cursor-pointer shadow-sm"
          >
            <Download className="w-4 h-4 mr-2" /> Download Evidence Report (Hash Verified)
          </button>
        </div>
      </header>

      {/* Main Grid Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        
        {/* Left Column: Risk Metrics & Single-Vector Simulation */}
        <div className="lg:col-span-2 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-2xl shadow-xl">
              <div className="flex justify-between items-start">
                <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Residual Risk Exposure</span>
                <Activity className="w-4 h-4 text-cyan-400" />
              </div>
              <div className="text-2xl font-bold mt-2 text-slate-100 flex flex-col">
                <span>₹{Math.round(riskExposure).toLocaleString()}</span>
                {monteCarlo && (
                  <span className="text-[10px] font-normal text-slate-400 mt-1">
                    Median (P50) – 95th percentile (P95): ₹{monteCarlo.p50_loss.toLocaleString()} – ₹{monteCarlo.p95_loss.toLocaleString()}
                  </span>
                )}
              </div>
              <span className="text-xs text-emerald-400 mt-1 block">Expected Annual Loss (EAL)</span>
            </div>

            <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-2xl shadow-xl">
              <div className="flex justify-between items-start">
                <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Budget Utilization</span>
                <Lock className="w-4 h-4 text-blue-400" />
              </div>
              <div className="mt-2 text-slate-100 space-y-1">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">Budget:</span>
                  <span className="font-bold">₹{totalBudget.toLocaleString()}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">Allocated:</span>
                  <span className="font-bold text-cyan-400">₹{budgetData ? budgetData.allocated.toLocaleString() : "0"}</span>
                </div>
                <div className="flex justify-between text-sm">
                  <span className="text-slate-400">Unspent:</span>
                  <span className="font-bold text-emerald-400">₹{budgetData ? budgetData.unspent.toLocaleString() : totalBudget.toLocaleString()}</span>
                </div>
              </div>
            </div>

            <div className="bg-[#111827] border border-[#1F2937] p-5 rounded-2xl shadow-xl">
              <div className="flex justify-between items-start">
                <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">Optimization Index</span>
                <TrendingDown className="w-4 h-4 text-emerald-400" />
              </div>
              <div className={`text-2xl font-bold mt-2 ${optimizationIndex.startsWith('A') ? 'text-emerald-400' : optimizationIndex.startsWith('B') ? 'text-amber-400' : optimizationIndex.startsWith('C') ? 'text-red-400' : 'text-slate-400'}`}>
                {optimizationIndex}
              </div>
              <span className="text-xs text-slate-400 mt-1 block">ROSI & Efficiency Grade</span>
            </div>
          </div>

          {/* Budget Control Panel */}
          <div className="bg-[#111827] border border-[#1F2937] p-6 rounded-2xl shadow-xl">
            <h2 className="text-lg font-bold text-slate-200 mb-2 flex items-center">
              <Layers className="w-5 h-5 mr-2 text-cyan-400" /> Security Budget Allocation
            </h2>
            <p className="text-sm text-slate-400 mb-6">
              Set your available capital budget. The optimizer will automatically select the best combination of security projects to maximize risk reduction.
            </p>

            <div className="space-y-6">
              <div>
                <div className="flex justify-between text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
                  <span>Available Capital</span>
                  <span className="text-cyan-400 font-bold text-sm">₹{totalBudget.toLocaleString()}</span>
                </div>
                <input 
                  type="range" min="0" max="10000000" step="100000"
                  value={totalBudget} 
                  onChange={(e) => setTotalBudget(Number(e.target.value))}
                  className="w-full accent-cyan-400 bg-slate-800 cursor-pointer h-2 rounded-lg"
                />
                <div className="flex justify-between text-xs text-slate-500 mt-2">
                  <span>₹0</span>
                  <span>₹1 Crore (10M)</span>
                </div>
              </div>

              <div className="pt-2">
                <button 
                  onClick={handleSimulate}
                  className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold py-3 px-4 rounded-xl transition shadow-lg shadow-cyan-500/10 flex items-center justify-center cursor-pointer"
                >
                  <RefreshCw className="w-4 h-4 mr-2" /> Optimize Portfolio & Recalculate Exposure
                </button>
              </div>
            </div>
          </div>

          {/* Asset Inventory Editor */}
          <div className="bg-[#111827] border border-[#1F2937] p-6 rounded-2xl shadow-xl mt-6">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-lg font-bold text-slate-100 flex items-center">
                <Database className="w-5 h-5 mr-2 text-pink-400" /> Asset Inventory & Valuation
              </h2>
              <button 
                onClick={() => setShowAssets(!showAssets)}
                className="text-xs bg-[#1F2937] hover:bg-[#374151] px-3 py-1.5 rounded transition"
              >
                {showAssets ? 'Hide Assets' : 'Edit Valuations'}
              </button>
            </div>
            
            {showAssets && (
              <div className="space-y-4 animate-in fade-in slide-in-from-top-4 duration-300">
                <p className="text-sm text-slate-400 mb-4">Adjust the financial value of assets to see how it affects the risk exposure and optimizer choices.</p>
                <div className="max-h-64 overflow-y-auto pr-2 space-y-3">
                  {assets.map((asset) => (
                    <div key={asset.asset_id} className="flex justify-between items-center bg-[#0B0F19] p-3 rounded-xl border border-[#1F2937]">
                      <div>
                        <h4 className="text-sm font-semibold text-slate-200">{asset.name}</h4>
                        <span className="text-[10px] text-slate-500">Criticality: {asset.criticality_weight}/10</span>
                      </div>
                      <div className="flex flex-col items-end">
                        <div className="flex items-center">
                          <span className="text-slate-400 mr-2 text-sm">₹</span>
                          <input 
                            type="number"
                            min="100000"
                            step="100000"
                            value={asset.financial_value}
                            onChange={(e) => handleAssetChange(asset.asset_id, e.target.value)}
                            className="bg-[#1F2937] border-none text-slate-200 text-sm rounded px-3 py-1.5 w-32 focus:ring-2 focus:ring-pink-500 outline-none"
                          />
                        </div>
                        <span className="text-[10px] text-slate-400 mt-1">{formatIndianCurrency(asset.financial_value)}</span>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="flex space-x-3 mt-4">
                  <button 
                    onClick={handleResetAssets}
                    className="w-1/3 bg-[#1F2937] hover:bg-slate-600 text-slate-300 font-semibold py-2 rounded-xl transition duration-200"
                  >
                    Reset to defaults
                  </button>
                  <button 
                    onClick={handleSaveAssets}
                    className="w-2/3 bg-[#1F2937] hover:bg-pink-600 hover:text-white text-pink-400 border border-pink-900/50 font-semibold py-2 rounded-xl transition duration-200"
                  >
                    Save Asset Valuations
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Funded Projects List */}
          {(selectedTasks.length > 0 || simulationMessage) && (
            <div className="bg-[#111827] border border-[#1F2937] p-6 rounded-2xl shadow-xl mt-6">
              <h2 className="text-lg font-bold text-emerald-400 mb-4 flex items-center">
                <Target className="w-5 h-5 mr-2" /> Funded Security Projects (Optimizer Output)
              </h2>
              {simulationMessage ? (
                <div className="text-amber-400 p-4 border border-amber-900/50 bg-amber-900/10 rounded-xl text-center font-medium">
                  {simulationMessage}
                </div>
              ) : (
                <div className="space-y-4">
                  {selectedTasks.map(task => (
                    <div key={task.task_id} className="bg-[#0B0F19] border border-[#1F2937] p-4 rounded-xl">
                      <div className="flex justify-between items-start mb-2">
                        <h3 className="font-bold text-slate-200">{task.name}</h3>
                        <span className="bg-emerald-900/30 text-emerald-400 text-xs px-2 py-1 rounded border border-emerald-800/50">
                          {task.category}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mb-3">Target Asset: {task.target_asset} {task.cve_id && `(${task.cve_id})`}</p>
                      
                      {/* Compliance Tags Display */}
                      {task.compliance_tags && task.compliance_tags.length > 0 && (
                        <div className="flex flex-wrap gap-2 mb-3">
                          {task.compliance_tags.map(tag => (
                            <span key={tag} className="bg-blue-900/30 text-blue-400 text-[10px] px-2 py-0.5 rounded-full border border-blue-800/50">
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}

                      <div className="grid grid-cols-3 gap-2 text-sm">
                        <div>
                          <span className="block text-xs text-slate-500">Implementation Cost</span>
                          <span className="font-mono text-slate-300">₹{task.cost.toLocaleString()}</span>
                        </div>
                        <div>
                          <span className="block text-xs text-slate-500">Risk Reduction (EAL)</span>
                          <span className="font-mono text-cyan-400">₹{task.risk_reduction.toLocaleString()}</span>
                        </div>
                        <div>
                          <span className="block text-xs text-slate-500">Efficiency Ratio</span>
                          <span className="font-mono text-emerald-400">
                            {typeof task.efficiency_ratio === 'number' ? task.efficiency_ratio.toFixed(2) : task.efficiency_ratio}x
                          </span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Column: Standby AI / Notes Panel */}
        <div className="bg-[#111827] border border-[#1F2937] p-6 rounded-2xl shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center space-x-2 border-b border-[#1F2937] pb-3 mb-4">
              <div className="w-3 h-3 rounded-full bg-slate-500"></div>
              <h2 className="text-md font-bold text-slate-200">AI Advisor (Standby Mode)</h2>
            </div>
            
            <div className="bg-[#0B0F19] border border-[#1F2937] p-4 rounded-xl text-sm text-slate-300 mb-4 min-h-[160px] leading-relaxed">
              {loading ? (
                <span className="text-cyan-400 animate-pulse">Processing request...</span>
              ) : (
                aiResponse
              )}
            </div>
          </div>

          <div className="flex flex-col space-y-3">
            <div className="flex flex-wrap gap-2">
              {suggestedQuestions.map((q, idx) => (
                <button
                  key={idx}
                  onClick={() => handleChipClick(q)}
                  className="bg-[#1F2937] hover:bg-slate-700 text-[10px] text-cyan-400 border border-[#374151] px-2 py-1 rounded-full text-left transition"
                >
                  {q}
                </button>
              ))}
            </div>
            <form onSubmit={handleAskAI} className="space-y-3">
              <input 
                type="text" 
                placeholder="Ask advisory engine..."
                value={aiQuery}
                onChange={(e) => setAiQuery(e.target.value)}
                className="w-full bg-[#0B0F19] border border-[#1F2937] rounded-xl px-4 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-cyan-500 transition"
              />
              <button 
                type="submit"
                className="w-full bg-[#1F2937] hover:bg-slate-800 text-slate-300 border border-slate-700 font-semibold py-2 px-4 rounded-xl text-sm transition cursor-pointer"
              >
                Consult Advisor
              </button>
            </form>
          </div>
        </div>

      </div>

      {/* Bottom Section: Persistent Audit Log History Table */}
      <div className="bg-[#111827] border border-[#1F2937] p-6 rounded-2xl shadow-xl">
        <div className="flex items-center justify-between mb-4 border-b border-[#1F2937] pb-3">
          <h2 className="text-lg font-bold text-slate-200 flex items-center">
            <History className="w-5 h-5 mr-2 text-cyan-400" /> Simulation Audit Trail (SQLite Persistent Logs)
          </h2>
          <span className="text-xs text-slate-400">Chronological Compliance History</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-[#0B0F19] text-xs uppercase text-slate-400 border-b border-[#1F2937]">
              <tr>
                <th className="p-3">Timestamp</th>
                <th className="p-3">Budget</th>
                <th className="p-3">Allocated</th>
                <th className="p-3">Quantified Exposure</th>
                <th className="p-3">Index Grade</th>
                <th className="p-3">Blockchain Ledger Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1F2937]">
              {auditLogs.length === 0 ? (
                <tr>
                  <td colSpan="6" className="p-4 text-center text-slate-500">No simulation records logged yet. Run a simulation above.</td>
                </tr>
              ) : (
                auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-[#1a2333] transition">
                    <td className="p-3 font-mono text-xs text-slate-400">{log.timestamp}</td>
                    <td className="p-3 font-semibold text-slate-200">₹{log.total_budget.toLocaleString()}</td>
                    <td className="p-3 font-semibold text-cyan-400">₹{log.allocated ? log.allocated.toLocaleString() : "0"}</td>
                    <td className="p-3 text-cyan-400 font-bold">₹{Math.round(log.risk_exposure).toLocaleString()}</td>
                    <td className={`p-3 font-semibold ${log.optimization_index.startsWith('A') ? 'text-emerald-400' : log.optimization_index.startsWith('B') ? 'text-amber-400' : log.optimization_index.startsWith('C') ? 'text-red-400' : 'text-slate-400'}`}>{log.optimization_index}</td>
                    <td className="p-3 font-mono text-[10px] text-slate-500 truncate max-w-[150px]" title={log.block_hash || "N/A"}>
                      {log.block_hash ? `${log.block_hash.substring(0,16)}...` : "Unverified"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
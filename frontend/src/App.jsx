import { useEffect, useMemo, useState } from "react";
import "./App.css";

const API = "http://127.0.0.1:8002";
async function apiFetch(url, options = {}) {
  const token = localStorage.getItem("websentinel_token");
  return fetch(url, {
    ...options,
    headers: { ...(options.headers || {}), ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
}

const dateText = (value) => {
  if (!value) return "Unknown time";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
};

function AuthPage({ onAuthenticated }) {
  const [mode, setMode] = useState(new URLSearchParams(window.location.search).has("reset_token") ? "reset" : "login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [working, setWorking] = useState(false);
  const [resetUrl, setResetUrl] = useState("");
  const resetToken = new URLSearchParams(window.location.search).get("reset_token") || "";

  async function submit(event) {
    event.preventDefault(); setError(""); setMessage(""); setWorking(true);
    try {
      let path = "/auth/login";
      let body = { email, password };
      if (mode === "signup") { path = "/auth/signup"; body = { name, email, password }; }
      if (mode === "forgot") { path = "/auth/forgot-password"; body = { email }; }
      if (mode === "reset") { path = "/auth/reset-password"; body = { token: resetToken, new_password: newPassword }; }
      const res = await fetch(`${API}${path}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Request failed.");
      if (mode === "login" || mode === "signup") { onAuthenticated(data.token); return; }
      setMessage(data.message || "Done.");
      if (data.development_reset_url) setResetUrl(data.development_reset_url);
      if (mode === "reset") { window.history.replaceState({}, "", window.location.pathname); setMode("login"); setPassword(""); setNewPassword(""); }
    } catch (e) { setError(e.message || "Something went wrong."); }
    finally { setWorking(false); }
  }

  const titles = { login: "Welcome back", signup: "Create your account", forgot: "Reset your password", reset: "Choose a new password" };
  return <div className="auth-screen">
    <div className="auth-decoration"><div className="auth-orb orb-one"/><div className="auth-orb orb-two"/><div className="auth-brand"><div className="auth-logo">🛡</div><p className="auth-eyebrow">WEB APPLICATION SECURITY</p><h1>WebSentinel</h1><p className="auth-tagline">Find weaknesses. Track improvements.</p><div className="auth-feature"><span>✓</span> Security configuration checks</div><div className="auth-feature"><span>✓</span> Scan history and reports</div><div className="auth-feature"><span>✓</span> Clear findings and recommendations</div></div></div>
    <div className="auth-side"><form className="auth-card" onSubmit={submit}>
      <p className="auth-eyebrow">SECURE WORKSPACE</p><h2>{titles[mode]}</h2><p className="auth-subtitle">{mode === "login" ? "Sign in to continue to your security dashboard." : mode === "signup" ? "Create an account to start using WebSentinel." : mode === "forgot" ? "Enter your account email to get a reset link." : "Your reset link is valid for 30 minutes."}</p>
      {mode === "signup" && <><label htmlFor="auth-name">Full name</label><input id="auth-name" autoComplete="name" value={name} onChange={e => setName(e.target.value)} required maxLength={80} placeholder="Your name"/></>}
      {mode !== "reset" && <><label htmlFor="auth-email">Email address</label><input id="auth-email" type="email" autoComplete="email" value={email} onChange={e => setEmail(e.target.value)} required maxLength={254} placeholder="you@example.com"/></>}
      {(mode === "login" || mode === "signup") && <><label htmlFor="auth-password">Password</label><input id="auth-password" type="password" autoComplete={mode === "signup" ? "new-password" : "current-password"} value={password} onChange={e => setPassword(e.target.value)} required minLength={8} maxLength={128} placeholder={mode === "signup" ? "At least 8 characters" : "Enter your password"}/></>}
      {mode === "reset" && <><label htmlFor="auth-new-password">New password</label><input id="auth-new-password" type="password" autoComplete="new-password" value={newPassword} onChange={e => setNewPassword(e.target.value)} required minLength={8} maxLength={128} placeholder="At least 8 characters"/></>}
      {error && <div className="auth-alert error" role="alert">{error}</div>}
      {message && <div className="auth-alert success" role="status">{message}</div>}
      {resetUrl && <div className="auth-alert dev-reset"><strong>Local development reset link</strong><a href={resetUrl}>Open password reset page</a><small>This link is shown only because email delivery is not configured. Do not use this development mode on a public deployment.</small></div>}
      <button className="primary auth-submit" type="submit" disabled={working}>{working ? "Please wait…" : mode === "login" ? "Sign in" : mode === "signup" ? "Create account" : mode === "forgot" ? "Send reset instructions" : "Reset password"}</button>
      <div className="auth-links">
        {mode === "login" && <><button type="button" onClick={() => { setMode("forgot"); setError(""); setMessage(""); }}>Forgot password?</button><p>New to WebSentinel? <button type="button" onClick={() => { setMode("signup"); setError(""); setMessage(""); }}>Create an account</button></p></>}
        {mode === "signup" && <p>Already have an account? <button type="button" onClick={() => { setMode("login"); setError(""); setMessage(""); }}>Sign in</button></p>}
        {mode === "forgot" && <p>Remembered your password? <button type="button" onClick={() => { setMode("login"); setError(""); setMessage(""); setResetUrl(""); }}>Back to sign in</button></p>}
        {mode === "reset" && <p><button type="button" onClick={() => { setMode("login"); window.history.replaceState({}, "", window.location.pathname); }}>Back to sign in</button></p>}
      </div>
      <p className="auth-footnote">Use an account you create here. Passwords are stored as salted password hashes.</p>
    </form></div>
  </div>;
}

function App() {
  const [authToken, setAuthToken] = useState(() => localStorage.getItem("websentinel_token") || "");
  const [view, setView] = useState("dashboard");
  const [target, setTarget] = useState("http://127.0.0.1:3000");
  const [status, setStatus] = useState("Checking");
  const [message, setMessage] = useState("Connecting to WebSentinel...");
  const [history, setHistory] = useState([]);
  const [scanResults, setScanResults] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [crawlLimit, setCrawlLimit] = useState("10");
  const [crawlResults, setCrawlResults] = useState(null);
  const [xssResults, setXssResults] = useState(null);
  const [compareA, setCompareA] = useState("");
  const [compareB, setCompareB] = useState("");

  async function loadHistory(silent = false) {
    if (!silent) setLoading(true);
    try {
      const res = await apiFetch(`${API}/history?limit=200`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Could not load history.");
      const items = data.scans || [];
      setHistory(items);
      if (items.length) {
        setCompareA((old) => old || String(items[0].id));
        setCompareB((old) => old || String(items[1]?.id ?? items[0].id));
      }
      return items;
    } catch (e) {
      if (!silent) setMessage(e.message || "Could not load scan history.");
      return [];
    } finally {
      if (!silent) setLoading(false);
    }
  }

  useEffect(() => {
    if (!authToken) return;
    let live = true;
    (async () => {
      try {
        const res = await apiFetch(`${API}/health`);
        if (!res.ok) throw new Error();
        const health = await res.json();
        const histRes = await apiFetch(`${API}/history?limit=200`);
        const histData = await histRes.json();
        if (!histRes.ok) throw new Error();
        if (!live) return;
        setStatus("Connected");
        setHistory(histData.scans || []);
        setMessage(`Backend connected · ${health.saved_scans} saved scans`);
        if (histData.scans?.length) {
          setScanResults(histData.scans[0]);
          setSelectedId(histData.scans[0].id);
          setCompareA(String(histData.scans[0].id));
          setCompareB(String(histData.scans[1]?.id ?? histData.scans[0].id));
        }
      } catch {
        if (live) {
          setStatus("Disconnected");
          setMessage("Backend unavailable. Keep the backend terminal running on port 8002.");
        }
      }
    })();
    return () => { live = false; };
  }, [authToken]);

  async function startScan() {
    if (!isAllowedTarget(target)) {
      setMessage("Enter a local lab URL on port 3000, 8080, or 8081, or an authorized public HTTP/HTTPS website.");
      return;
    }
    setScanning(true);
    setStatus("Scanning");
    setMessage("Checking target security configuration...");
    try {
      const res = await apiFetch(`${API}/scan`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Scan failed.");
      setScanResults(data);
      setSelectedId(data.id);
      setStatus("Scan complete");
      setMessage(`Scan #${data.id} saved. ${data.headers_checked} checks performed.`);
      await loadHistory(true);
      setView("dashboard");
    } catch (e) {
      setStatus("Scan failed");
      setMessage(e.message || "Scan failed.");
    } finally {
      setScanning(false);
    }
  }

  function isAllowedTarget(value) {
    try {
      const u = new URL(value.trim());
      if (!["http:", "https:"].includes(u.protocol) || !u.hostname || u.username || u.password) return false;
      const host = u.hostname.toLowerCase();
      const localHosts = ["127.0.0.1", "localhost", "[::1]"];
      if (localHosts.includes(host)) {
        return u.protocol === "http:" && ["3000", "8080", "8081"].includes(u.port);
      }
      return !u.port || ["80", "443"].includes(u.port);
    } catch { return false; }
  }

  async function openScan(id) {
    try {
      const res = await apiFetch(`${API}/history/${id}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Could not open scan.");
      setScanResults(data);
      setSelectedId(data.id);
      setTarget(data.target);
      setView("dashboard");
      setMessage(`Viewing saved scan #${data.id} · ${dateText(data.scanned_at)}`);
    } catch (e) { setMessage(e.message || "Could not open scan."); }
  }

  async function downloadReport(kind, id = selectedId) {
    if (!id) { setMessage("Run a scan first."); return; }
    setBusy(true);
    try {
      const path = kind === "pdf" ? "/report.pdf" : "/report";
      const res = await apiFetch(`${API}${path}?scan_id=${encodeURIComponent(id)}`);
      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.detail || `Could not download ${kind.toUpperCase()} report.`);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `websentinel-report-${id}.${kind === "pdf" ? "pdf" : "html"}`;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      setMessage(`${kind.toUpperCase()} report for scan #${id} downloaded.`);
    } catch (e) { setMessage(e.message || "Report download failed."); }
    finally { setBusy(false); }
  }

  async function runCrawl() {
    if (!isAllowedTarget(target)) { setMessage("Enter a local lab URL on port 3000, 8080, or 8081, or an authorized public HTTP/HTTPS website."); return; }
    setBusy(true); setCrawlResults(null); setMessage("Crawling same-origin HTML pages...");
    try {
      const res = await apiFetch(`${API}/crawl`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim(), max_pages: Number(crawlLimit) }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Crawler failed.");
      setCrawlResults(data);
      setMessage(`Crawl complete · ${data.pages_visited} page(s) visited.`);
    } catch (e) { setMessage(e.message || "Crawler failed."); }
    finally { setBusy(false); }
  }

  async function runXssCheck() {
    if (!isAllowedTarget(target)) { setMessage("Enter a local lab URL on port 3000, 8080, or 8081, or an authorized public HTTP/HTTPS website."); return; }
    setBusy(true); setXssResults(null); setMessage("Running a harmless plain-text reflection check...");
    try {
      const res = await apiFetch(`${API}/xss-check`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || "Reflection check failed.");
      setXssResults(data);
      setMessage("Reflection check complete.");
    } catch (e) { setMessage(e.message || "Reflection check failed."); }
    finally { setBusy(false); }
  }

  const currentFindings = scanResults?.findings || [];
  const filteredFindings = useMemo(() => currentFindings.filter((f) => {
    const severityOk = severityFilter === "All" || f.severity === severityFilter;
    const statusOk = statusFilter === "All" ||
      (statusFilter === "Present" && f.present) ||
      (statusFilter === "Needs review" && !f.present && f.severity !== "Info") ||
      (statusFilter === "Not assessed" && !f.present && f.severity === "Info");
    return severityOk && statusOk;
  }), [currentFindings, severityFilter, statusFilter]);

  const firstCompare = history.find((x) => String(x.id) === String(compareA));
  const secondCompare = history.find((x) => String(x.id) === String(compareB));
  const delta = firstCompare && secondCompare
    ? secondCompare.missing_headers - firstCompare.missing_headers : null;

  const navItems = [
    ["dashboard", "▦ Dashboard"], ["newscan", "⌕ New Scan"], ["history", "◷ Scan History"],
    ["crawler", "⌘ Website Crawler"], ["xss", "⚑ Safe XSS Check"],
    ["compare", "⇄ Compare Scans"], ["reports", "▤ Reports"],
  ];
  const title = {
    dashboard: "Dashboard", newscan: "New Scan", history: "Scan History",
    crawler: "Website Crawler", xss: "Safe XSS Check", compare: "Compare Scans", reports: "Reports",
  }[view];

  if (!authToken) return <AuthPage onAuthenticated={(token) => { localStorage.setItem("websentinel_token", token); setAuthToken(token); }} />;

  return <div className="app">
    <aside className="sidebar">
      <h2>🛡️ WebSentinel</h2><p className="muted">Security Scanner</p>
      <nav aria-label="Main navigation">
        {navItems.map(([key, label]) => <button key={key} className={`nav-item ${view === key ? "active" : ""}`} onClick={() => setView(key)}>{label}</button>)}
      </nav>
      <p className="sidebar-note">Local security lab · SQLite history</p>
    </aside>
    <main className="main">
      <header className="topbar">
        <div><h1>{title}</h1><p className="muted">Web application security workspace</p></div>
        <div className="topbar-actions"><span className={`status-badge ${status === "Disconnected" ? "offline" : ""}`}>● {status}</span><button className="secondary compact" onClick={async () => { try { await apiFetch(`${API}/auth/logout`, { method: "POST" }); } catch {} localStorage.removeItem("websentinel_token"); setAuthToken(""); setHistory([]); setScanResults(null); }}>Log out</button></div>
      </header>

      <section className="welcome">
        <div><p className="eyebrow">SECURITY WORKSPACE</p><h2>Find weaknesses. Track improvements.</h2>
          <p>Scan and review authorized local lab applications.</p></div><div className="shield">🛡️</div>
      </section>

      <section className="stats">
        <div className="stat-card"><span>Total Saved Scans</span><strong>{history.length}</strong><small>Stored in SQLite</small></div>
        <div className="stat-card"><span>Risk Score</span><strong>{scanResults?.risk?.score ?? "—"}<small>{scanResults?.risk ? "/100" : ""}</small></strong><small>{scanResults?.risk?.label || "Run a scan"}</small></div>
        <div className="stat-card"><span>Items for Review</span><strong>{scanResults?.missing_headers ?? "—"}</strong><small>Selected scan</small></div>
        <div className="stat-card"><span>HTTP Status</span><strong>{scanResults?.http_status ?? "—"}</strong><small>Selected scan</small></div>
      </section>

      {(view === "dashboard" || view === "newscan") && <>
        <section className="panel">
          <div className="panel-heading"><div><h2>Start a Security Scan</h2><p className="muted">Scan local labs or public websites you are authorized to test.</p></div><span>⌕</span></div>
          <label htmlFor="target">Target URL</label>
          <input id="target" value={target} onChange={(e) => setTarget(e.target.value)} disabled={scanning || busy} placeholder="https://your-authorized-site.com"/>
          <p className="hint">Local labs: ports 3000, 8080, 8081. Public sites: HTTP/HTTPS on ports 80/443. Only scan sites you own or have permission to test.</p>
          <div className="actions"><button className="primary" onClick={startScan} disabled={scanning || busy}>{scanning ? "Scanning..." : "Start Scan →"}</button>
            <button className="secondary" onClick={() => loadHistory()} disabled={loading}>Refresh History</button></div>
          <div className="message" role="status">{message}</div>
        </section>
        <section className="panel">
          <div className="report-heading"><div><h2>Selected Scan Findings</h2><p className="muted">Evidence and recommended next steps.</p></div>
            <div className="actions tight"><button className="secondary" onClick={() => downloadReport("html")} disabled={!selectedId || busy}>HTML Report</button><button className="primary" onClick={() => downloadReport("pdf")} disabled={!selectedId || busy}>PDF Report</button></div></div>
          {!scanResults ? <div className="empty-state"><span>✓</span><h3>No scan selected</h3><p>Run a scan to see findings.</p></div> : <>
            <div className="results-summary">
              <p><strong>Scan:</strong> #{scanResults.id}</p><p><strong>Target:</strong> {scanResults.target}</p>
              <p><strong>Time:</strong> {dateText(scanResults.scanned_at)}</p><p><strong>Risk method:</strong> Heuristic, not a validated security rating.</p>
            </div>
            <div className="filter-row">
              <div><label htmlFor="severity">Severity</label><select id="severity" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select></div>
              <div><label htmlFor="finding-status">Finding status</label><select id="finding-status" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}><option>All</option><option>Present</option><option>Needs review</option><option>Not assessed</option></select></div>
              <span className="muted">{filteredFindings.length} of {currentFindings.length} findings</span>
            </div>
            <div className="findings-list">{filteredFindings.map((f, i) => <article className="finding" key={`${f.header}-${i}`}>
              <div className="finding-top"><strong>{f.header}</strong><span className={`finding-badge ${f.present ? "present" : "missing"}`}>{f.present ? "Present / Info" : f.severity === "Info" ? "Not assessed" : "Needs review"}</span></div>
              <p>{f.message}</p><small>Severity: {f.severity || "Unspecified"}</small>
              {f.evidence && <p className="evidence"><strong>Evidence:</strong> {f.evidence}</p>}
              {f.recommendation && <p className="recommendation"><strong>Recommendation:</strong> {f.recommendation}</p>}
            </article>)}</div>
            <p className="hint">{scanResults.note}</p>
            {scanResults.risk && <p className="hint">Risk score: {scanResults.risk.score}/100 ({scanResults.risk.label}). {scanResults.risk.method}</p>}
          </>}
          <div className="message" role="status">{message}</div>
        </section>
      </>}

      {view === "history" && <section className="panel">
        <div className="report-heading"><div><h2>Saved Scans</h2><p className="muted">History remains available after backend restarts.</p></div><button className="secondary" onClick={() => loadHistory()} disabled={loading}>{loading ? "Loading..." : "↻ Refresh"}</button></div>
        {history.length === 0 ? <div className="empty-state"><h3>No saved scans yet</h3></div> : <div className="history-list">{history.map((item) => <article key={item.id} className={`history-item ${selectedId === item.id ? "selected" : ""}`}>
          <div className="history-main"><div className="history-title"><strong>Scan #{item.id}</strong><span className={`mini-badge ${item.missing_headers ? "warning" : "good"}`}>{item.missing_headers} review items</span></div>
            <p className="history-target">{item.target}</p><small>{dateText(item.scanned_at)} · HTTP {item.http_status} · Risk {item.risk?.score ?? "—"}/100</small></div>
          <div className="history-actions"><button className="secondary compact" onClick={() => openScan(item.id)}>View</button><button className="secondary compact" onClick={() => downloadReport("pdf", item.id)} disabled={busy}>PDF</button><button className="secondary compact" onClick={() => downloadReport("html", item.id)} disabled={busy}>HTML</button></div>
        </article>)}</div>}
      </section>}

      {view === "crawler" && <section className="panel">
        <h2>Website Crawler</h2><p className="muted">Passively discovers same-origin HTML links. Does not submit forms or follow redirects.</p>
        <label htmlFor="crawl-limit">Maximum pages</label><select id="crawl-limit" value={crawlLimit} onChange={(e) => setCrawlLimit(e.target.value)}><option value="5">5 pages</option><option value="10">10 pages</option><option value="20">20 pages</option><option value="30">30 pages</option></select>
        <div className="actions"><button className="primary" onClick={runCrawl} disabled={busy || scanning}>{busy ? "Working..." : "Start Crawl"}</button></div>
        {crawlResults && <><div className="results-summary"><p><strong>Pages visited:</strong> {crawlResults.pages_visited}</p><p><strong>Checks performed:</strong> {crawlResults.findings_checked}</p></div>
          <div className="history-list">{crawlResults.pages.map((p, i) => <article className="history-item" key={`${p.url}-${i}`}><div className="history-main"><strong>{p.url}</strong><p>{p.note}</p><small>HTTP {p.status ?? "Request failed"} · {p.content_type || "Unknown content type"} · {p.missing_headers ?? 0} review items</small></div></article>)}</div>
          <p className="hint">{crawlResults.note}</p></>}
        <div className="message" role="status">{message}</div>
      </section>}

      {view === "xss" && <section className="panel">
        <h2>Safe XSS Reflection Check</h2><p className="muted">Sends a plain-text marker only. It does not execute JavaScript and cannot confirm XSS.</p>
        <label htmlFor="xss-target">Target URL</label><input id="xss-target" value={target} onChange={(e) => setTarget(e.target.value)} disabled={busy} />
        <div className="actions"><button className="primary" onClick={runXssCheck} disabled={busy || scanning}>{busy ? "Checking..." : "Run Safe Reflection Check"}</button></div>
        {xssResults && <div className="result-box"><h3>{xssResults.canary_reflected ? "Marker reflected" : "Marker not reflected"}</h3><p>{xssResults.result}</p><p><strong>HTTP status:</strong> {xssResults.http_status}</p><p className="hint">{xssResults.note}</p></div>}
        <div className="message" role="status">{message}</div>
      </section>}

      {view === "compare" && <section className="panel">
        <h2>Compare Saved Scans</h2><p className="muted">Compare review-item counts and scores between two stored scans.</p>
        <div className="compare-selects"><div><label htmlFor="compare-a">Earlier / baseline scan</label><select id="compare-a" value={compareA} onChange={(e) => setCompareA(e.target.value)}>{history.map((h) => <option key={h.id} value={h.id}>Scan #{h.id} · {dateText(h.scanned_at)}</option>)}</select></div>
          <div><label htmlFor="compare-b">Later / comparison scan</label><select id="compare-b" value={compareB} onChange={(e) => setCompareB(e.target.value)}>{history.map((h) => <option key={h.id} value={h.id}>Scan #{h.id} · {dateText(h.scanned_at)}</option>)}</select></div></div>
        {!firstCompare || !secondCompare ? <div className="empty-state"><p>Run at least one scan to compare results.</p></div> : <div className="results-summary">
          <p><strong>Baseline:</strong> Scan #{firstCompare.id}<br/>Review items: {firstCompare.missing_headers}<br/>Risk: {firstCompare.risk?.score ?? "—"}/100</p>
          <p><strong>Comparison:</strong> Scan #{secondCompare.id}<br/>Review items: {secondCompare.missing_headers}<br/>Risk: {secondCompare.risk?.score ?? "—"}/100</p>
          <p><strong>Review-item change:</strong> {delta > 0 ? `+${delta} more` : delta < 0 ? `${Math.abs(delta)} fewer` : "No change"}</p>
          <p><strong>Risk-score change:</strong> {(secondCompare.risk?.score ?? 0) - (firstCompare.risk?.score ?? 0) > 0 ? "+" : ""}{(secondCompare.risk?.score ?? 0) - (firstCompare.risk?.score ?? 0)} points</p>
        </div>}
        <p className="hint">Comparisons use saved summary counts and the heuristic risk score. They do not establish whether a real vulnerability was fixed.</p>
      </section>}

      {view === "reports" && <section className="panel">
        <h2>Reports</h2><p className="muted">Download PDF or HTML reports for any saved scan.</p>
        {history.length === 0 ? <p>No saved scans yet.</p> : <div className="history-list">{history.map((item) => <article className="history-item" key={item.id}>
          <div className="history-main"><strong>Scan #{item.id}</strong><p className="history-target">{item.target}</p><small>{dateText(item.scanned_at)} · Risk {item.risk?.score ?? "—"}/100</small></div>
          <div className="history-actions"><button className="secondary compact" onClick={() => downloadReport("html", item.id)} disabled={busy}>HTML</button><button className="primary compact" onClick={() => downloadReport("pdf", item.id)} disabled={busy}>PDF</button></div>
        </article>)}</div>}
        <p className="hint">PDF reports require the one-time ReportLab installation in the instructions.</p>
        <div className="message" role="status">{message}</div>
      </section>}

      <footer>WebSentinel · Local lab use only · Risk score is heuristic</footer>
    </main>
  </div>;
}

export default App;

import { useState } from "react";
import jsPDF from "jspdf";
import "./App.css";

// ============================================================
// API CONFIGURATION
// ============================================================
// Local backend:
// http://127.0.0.1:5000
//
// For Netlify later, create:
// VITE_API_BASE_URL=https://your-backend-url.com
// ============================================================

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000";

function App() {
  const [page, setPage] = useState("overview");
  const [selectedFile, setSelectedFile] = useState(null);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");

  const [settings, setSettings] = useState({
    notifications: true,
    autoAnalysis: true,
    evidenceProtection: true,
  });

  // ============================================================
  // SAFE DATA ACCESS
  // ============================================================

  const email = analysisResult?.email || {};
  const auth = analysisResult?.authentication || {};
  const identity = analysisResult?.identity_analysis || {};
  const urls = analysisResult?.url_analysis || {};
  const threat = analysisResult?.threat_analysis || {};
  const confidence = analysisResult?.confidence || {};
  const ipAnalysis = analysisResult?.ip_analysis || {};
  const evidence = analysisResult?.evidence || {};

  const riskScore = threat.risk_score ?? 0;
  const riskLevel = threat.risk_level || "LOW";
  const verdict = threat.verdict || "LOW RISK";

  const indicators = Array.isArray(analysisResult?.indicators)
    ? analysisResult.indicators
    : [];

  // ============================================================
  // RISK CLASS
  // ============================================================

  const getRiskClass = () => {
    const level = String(riskLevel).toUpperCase();

    if (level === "CRITICAL") return "critical";
    if (level === "HIGH") return "high";
    if (level === "MEDIUM") return "medium";

    return "low";
  };

  // ============================================================
  // FILE SELECTION
  // ============================================================

  const handleFileChange = (event) => {
    const file = event.target.files?.[0];

    if (!file) {
      return;
    }

    setError("");

    if (!file.name.toLowerCase().endsWith(".eml")) {
      setSelectedFile(null);
      setError("Please select a valid .eml email file.");
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      setSelectedFile(null);
      setError("File size must be less than 10 MB.");
      return;
    }

    setSelectedFile(file);
  };

  // ============================================================
  // LIVE EMAIL ANALYSIS
  // ============================================================

  const handleAnalyze = async () => {
    if (!selectedFile) {
      setError("Please select an .eml file first.");
      return;
    }

    setLoading(true);
    setError("");
    setAnalysisResult(null);

    try {
      const formData = new FormData();

      formData.append("email", selectedFile);

      const response = await fetch(
        `${API_BASE_URL}/analyze-email`,
        {
          method: "POST",
          body: formData,
        }
      );

      let data;

      try {
        data = await response.json();
      } catch {
        throw new Error(
          "The backend returned an invalid response."
        );
      }

      if (!response.ok) {
        throw new Error(
          data?.error || "Email analysis failed."
        );
      }

      if (!data || typeof data !== "object") {
        throw new Error(
          "Invalid analysis response received from backend."
        );
      }

      // Save complete forensic report
      setAnalysisResult(data);

      // Automatically open analysis page
      setPage("analysis");

    } catch (err) {
      console.error("Email analysis error:", err);

      setError(
        err?.message ||
          "Could not connect to the Email Threat Detection backend."
      );
    } finally {
      setLoading(false);
    }
  };

  // ============================================================
  // RESET
  // ============================================================

  const resetAnalysis = () => {
    setSelectedFile(null);
    setAnalysisResult(null);
    setError("");
    setPage("upload");
  };

  // ============================================================
  // DOWNLOAD JSON REPORT
  // ============================================================

  const downloadJSON = () => {
    if (!analysisResult) {
      return;
    }

    const blob = new Blob(
      [
        JSON.stringify(
          analysisResult,
          null,
          2
        ),
      ],
      {
        type: "application/json",
      }
    );

    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");

    a.href = url;

    a.download = `forensic-report-${
      analysisResult.report_id || "email"
    }.json`;

    document.body.appendChild(a);

    a.click();

    a.remove();

    URL.revokeObjectURL(url);
  };

  // ============================================================
  // GENERATE PDF
  // ============================================================

  const generatePDF = () => {
    if (!analysisResult) {
      return;
    }

    const doc = new jsPDF();

    let y = 20;

    const addLine = (text, size = 11) => {
      doc.setFontSize(size);

      const lines = doc.splitTextToSize(
        String(text),
        175
      );

      if (
        y + lines.length * 7 >
        280
      ) {
        doc.addPage();
        y = 20;
      }

      doc.text(lines, 15, y);

      y += lines.length * 7;
    };

    // ------------------------------------------------------------
    // TITLE
    // ------------------------------------------------------------

    doc.setFont(
      "helvetica",
      "bold"
    );

    doc.setFontSize(18);

    doc.text(
      "MAILTRACE FORENSIC EMAIL REPORT",
      15,
      y
    );

    y += 12;

    doc.setFont(
      "helvetica",
      "normal"
    );

    // ------------------------------------------------------------
    // REPORT INFORMATION
    // ------------------------------------------------------------

    addLine(
      `Report ID: ${
        analysisResult.report_id || "N/A"
      }`
    );

    addLine(
      `Analysis Version: ${
        analysisResult.analysis_version || "N/A"
      }`
    );

    addLine(
      `File: ${
        evidence.original_filename ||
        selectedFile?.name ||
        "N/A"
      }`
    );

    addLine(
      `SHA-256: ${
        evidence.sha256 || "N/A"
      }`
    );

    y += 4;

    // ------------------------------------------------------------
    // THREAT ASSESSMENT
    // ------------------------------------------------------------

    doc.setFont(
      "helvetica",
      "bold"
    );

    addLine(
      "THREAT ASSESSMENT",
      14
    );

    doc.setFont(
      "helvetica",
      "normal"
    );

    addLine(
      `Risk Score: ${riskScore}/100`
    );

    addLine(
      `Risk Level: ${riskLevel}`
    );

    addLine(
      `Verdict: ${verdict}`
    );

    addLine(
      `Confidence: ${
        confidence.score ??
        confidence.confidence_score ??
        "N/A"
      }`
    );

    y += 4;

    // ------------------------------------------------------------
    // EMAIL INFORMATION
    // ------------------------------------------------------------

    doc.setFont(
      "helvetica",
      "bold"
    );

    addLine(
      "EMAIL INFORMATION",
      14
    );

    doc.setFont(
      "helvetica",
      "normal"
    );

    addLine(
      `From: ${email.from || "N/A"}`
    );

    addLine(
      `To: ${email.to || "N/A"}`
    );

    addLine(
      `Subject: ${
        email.subject || "N/A"
      }`
    );

    addLine(
      `Reply-To: ${
        email.reply_to || "N/A"
      }`
    );

    addLine(
      `Return-Path: ${
        email.return_path || "N/A"
      }`
    );

    addLine(
      `Message-ID: ${
        email.message_id || "N/A"
      }`
    );

    y += 4;

    // ------------------------------------------------------------
    // AUTHENTICATION
    // ------------------------------------------------------------

    doc.setFont(
      "helvetica",
      "bold"
    );

    addLine(
      "AUTHENTICATION",
      14
    );

    doc.setFont(
      "helvetica",
      "normal"
    );

    addLine(
      `SPF: ${auth.spf || "N/A"}`
    );

    addLine(
      `DKIM: ${auth.dkim || "N/A"}`
    );

    addLine(
      `DMARC: ${auth.dmarc || "N/A"}`
    );

    y += 4;

    // ------------------------------------------------------------
    // IDENTITY ANALYSIS
    // ------------------------------------------------------------

    doc.setFont(
      "helvetica",
      "bold"
    );

    addLine(
      "IDENTITY ANALYSIS",
      14
    );

    doc.setFont(
      "helvetica",
      "normal"
    );

    addLine(
      `Sender Domain: ${
        identity.sender_domain ||
        email.sender_domain ||
        "N/A"
      }`
    );

    addLine(
      `Lookalike Domain: ${
        identity.lookalike_domain_detected
          ? "YES"
          : "NO"
      }`
    );

    addLine(
      `Reply-To Mismatch: ${
        identity.reply_to_mismatch
          ? "YES"
          : "NO"
      }`
    );

    addLine(
      `Return-Path Mismatch: ${
        identity.return_path_mismatch
          ? "YES"
          : "NO"
      }`
    );

    addLine(
      `Message-ID Mismatch: ${
        identity.message_id_mismatch
          ? "YES"
          : "NO"
      }`
    );

    y += 4;

    // ------------------------------------------------------------
    // IP ANALYSIS
    // ------------------------------------------------------------

    doc.setFont(
      "helvetica",
      "bold"
    );

    addLine(
      "IP ANALYSIS",
      14
    );

    doc.setFont(
      "helvetica",
      "normal"
    );

    addLine(
      `Candidate Origin IP: ${
        ipAnalysis.candidate_origin_ip ||
        ipAnalysis.origin_ip ||
        "Not identified"
      }`
    );

    y += 4;

    // ------------------------------------------------------------
    // URL ANALYSIS
    // ------------------------------------------------------------

    doc.setFont(
      "helvetica",
      "bold"
    );

    addLine(
      "URL ANALYSIS",
      14
    );

    doc.setFont(
      "helvetica",
      "normal"
    );

    addLine(
      `Total URLs: ${
        urls.total_urls ?? 0
      }`
    );

    addLine(
      `Suspicious URLs: ${
        urls.suspicious_count ?? 0
      }`
    );

    const urlList =
      urls.urls ||
      urls.details ||
      [];

    if (Array.isArray(urlList)) {
      urlList.forEach(
        (item, index) => {
          const value =
            typeof item === "string"
              ? item
              : item?.url ||
                item?.domain ||
                JSON.stringify(item);

          addLine(
            `${index + 1}. ${value}`
          );
        }
      );
    }

    y += 4;

    // ------------------------------------------------------------
    // THREAT INDICATORS
    // ------------------------------------------------------------

    doc.setFont(
      "helvetica",
      "bold"
    );

    addLine(
      "THREAT INDICATORS",
      14
    );

    doc.setFont(
      "helvetica",
      "normal"
    );

    if (
      Array.isArray(indicators) &&
      indicators.length > 0
    ) {
      indicators.forEach(
        (indicator, index) => {
          const text =
            typeof indicator === "string"
              ? indicator
              : indicator?.description ||
                indicator?.name ||
                JSON.stringify(indicator);

          addLine(
            `${index + 1}. ${text}`
          );
        }
      );
    } else {
      addLine(
        "No significant threat indicators detected."
      );
    }

    // ------------------------------------------------------------
    // SAVE
    // ------------------------------------------------------------

    doc.save(
      `forensic-report-${
        analysisResult.report_id ||
        "email"
      }.pdf`
    );
  };

  // ============================================================
  // STATUS BADGE
  // ============================================================

  const renderStatus = (value) => {
    const normalized =
      String(
        value || "N/A"
      ).toUpperCase();

    let className =
      "status-neutral";

    if (
      normalized.includes("PASS") ||
      normalized === "LOW"
    ) {
      className =
        "status-pass";
    }

    if (
      normalized.includes("FAIL") ||
      normalized.includes("SUSPICIOUS") ||
      normalized.includes("HIGH") ||
      normalized.includes("CRITICAL")
    ) {
      className =
        "status-fail";
    }

    return (
      <span
        className={`status-badge ${className}`}
      >
        {value || "N/A"}
      </span>
    );
  };

  // ============================================================
  // NAVIGATION
  // ============================================================

  const navigation = [
    {
      id: "overview",
      label: "Overview",
      icon: "⌂",
    },
    {
      id: "threats",
      label: "Threat Detection",
      icon: "⚠",
    },
    {
      id: "verification",
      label: "Verification",
      icon: "✓",
    },
    {
      id: "blockchain",
      label: "Blockchain Evidence",
      icon: "▣",
    },
    {
      id: "upload",
      label: "Analyze Email",
      icon: "↑",
    },
    {
      id: "investigation",
      label: "Investigation",
      icon: "⌕",
    },
    {
      id: "report",
      label: "Forensic Report",
      icon: "▤",
    },
    {
      id: "settings",
      label: "Settings",
      icon: "⚙",
    },
  ];

  // ============================================================
  // SIDEBAR
  // ============================================================

  const renderSidebar = () => (
    <aside className="sidebar">
      <div className="logo-area">
        <div className="logo-icon">
          M
        </div>

        <div>
          <div className="logo-title">
            MAILTRACE
          </div>

          <div className="logo-subtitle">
            EMAIL FORENSICS
          </div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navigation.map(
          (item) => (
            <button
              key={item.id}
              className={`nav-item ${
                page === item.id
                  ? "active"
                  : ""
              }`}
              onClick={() =>
                setPage(item.id)
              }
            >
              <span className="nav-icon">
                {item.icon}
              </span>

              <span>
                {item.label}
              </span>
            </button>
          )
        )}
      </nav>

      <div className="sidebar-footer">
        <div className="system-status">
          <span className="status-dot"></span>

          <span>
            System Operational
          </span>
        </div>
      </div>
    </aside>
  );

  // ============================================================
  // TOP BAR
  // ============================================================

  const renderTopbar = () => (
    <header className="topbar">
      <div>
        <h1>
          {
            navigation.find(
              (item) =>
                item.id === page
            )?.label ||
              "Mailtrace"
          }
        </h1>

        <p>
          AI-Powered Email Threat Detection
          & Forensics
        </p>
      </div>

      <div className="topbar-right">
        <input
          type="text"
          placeholder="Search..."
          value={search}
          onChange={(e) =>
            setSearch(
              e.target.value
            )
          }
          className="search-input"
        />

        <div className="profile">
          <div className="profile-avatar">
            A
          </div>

          <div>
            <strong>
              Analyst
            </strong>

            <small>
              Security Operations
            </small>
          </div>
        </div>
      </div>
    </header>
  );

  // ============================================================
  // OVERVIEW
  // ============================================================

  const renderOverview = () => (
    <>
      <div className="page-heading">
        <h2>
          Email Threat Intelligence Dashboard
        </h2>

        <p>
          Analyze email messages and generate
          forensic intelligence from their
          headers, authentication records,
          URLs and routing data.
        </p>
      </div>

      <div className="dashboard-grid">
        <div className="dashboard-card">
          <span>
            Total Analyses
          </span>

          <strong>
            {analysisResult ? "1" : "0"}
          </strong>

          <small>
            Current session
          </small>
        </div>

        <div className="dashboard-card">
          <span>
            Threat Status
          </span>

          <strong
            className={
              analysisResult
                ? getRiskClass()
                : ""
            }
          >
            {analysisResult
              ? riskLevel
              : "READY"}
          </strong>

          <small>
            {analysisResult
              ? verdict
              : "Awaiting analysis"}
          </small>
        </div>

        <div className="dashboard-card">
          <span>
            Authentication
          </span>

          <strong>
            {analysisResult
              ? `${auth.spf || "N/A"} / ${
                  auth.dkim || "N/A"
                }`
              : "READY"}
          </strong>

          <small>
            SPF / DKIM
          </small>
        </div>

        <div className="dashboard-card">
          <span>
            Confidence
          </span>

          <strong>
            {analysisResult
              ? `${
                  confidence.score ??
                  confidence.confidence_score ??
                  0
                }`
              : "0"}
          </strong>

          <small>
            Analysis confidence
          </small>
        </div>
      </div>

      <div className="content-grid">
        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>
                Quick Email Analysis
              </h3>

              <p>
                Upload an email for
                forensic inspection.
              </p>
            </div>
          </div>

          <button
            className="primary-button"
            onClick={() =>
              setPage("upload")
            }
          >
            Analyze Email
          </button>
        </section>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h3>
                Detection Engine
              </h3>

              <p>
                Current analysis
                capabilities
              </p>
            </div>
          </div>

          <ul className="feature-list">
            <li>
              ✓ Email header forensics
            </li>

            <li>
              ✓ SPF / DKIM / DMARC analysis
            </li>

            <li>
              ✓ Sender identity correlation
            </li>

            <li>
              ✓ Suspicious URL detection
            </li>

            <li>
              ✓ IP extraction and origin analysis
            </li>

            <li>
              ✓ Risk scoring and confidence assessment
            </li>
          </ul>
        </section>
      </div>
    </>
  );

  // ============================================================
  // UPLOAD
  // ============================================================

  const renderUpload = () => (
    <>
      <div className="page-heading">
        <h2>
          Analyze Email
        </h2>

        <p>
          Upload an original .eml file to
          perform AI-assisted forensic analysis.
        </p>
      </div>

      <div className="upload-container">
        <div className="upload-card">
          <div className="upload-icon">
            ✉
          </div>

          <h3>
            Upload Email Evidence
          </h3>

          <p>
            Select an email file.
            Maximum file size:
            <strong> 10 MB</strong>
          </p>

          <label className="file-upload">
            <input
              type="file"
              accept=".eml,message/rfc822"
              onChange={
                handleFileChange
              }
            />

            <span>
              Select .eml File
            </span>
          </label>

          {selectedFile && (
            <div className="selected-file">
              <strong>
                {selectedFile.name}
              </strong>

              <span>
                {(
                  selectedFile.size /
                  1024
                ).toFixed(1)}{" "}
                KB
              </span>
            </div>
          )}

          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          <button
            className="analyze-button"
            onClick={
              handleAnalyze
            }
            disabled={
              !selectedFile ||
              loading
            }
          >
            {loading
              ? "Analyzing Email..."
              : "Analyze Email"}
          </button>

          {loading && (
            <div className="loading-message">
              Extracting headers,
              authentication data,
              URLs and threat indicators...
            </div>
          )}
        </div>
      </div>
    </>
  );

  // ============================================================
  // ANALYSIS
  // ============================================================

  const renderAnalysis = () => {
    if (!analysisResult) {
      return (
        <div className="empty-state">
          <h2>
            No Analysis Available
          </h2>

          <p>
            Upload an email first.
          </p>

          <button
            className="primary-button"
            onClick={() =>
              setPage("upload")
            }
          >
            Upload Email
          </button>
        </div>
      );
    }

    return (
      <>
        <div className="page-heading">
          <h2>
            Email Threat Analysis
          </h2>

          <p>
            Results generated dynamically
            from the uploaded email.
          </p>
        </div>

        <div className="risk-summary">
          <div
            className={`risk-score ${getRiskClass()}`}
          >
            <span>
              Risk Score
            </span>

            <strong>
              {riskScore}
            </strong>

            <small>
              / 100
            </small>
          </div>

          <div className="risk-status">
            <span>
              Threat Assessment
            </span>

            <strong>
              {verdict}
            </strong>

            <div>
              {renderStatus(
                riskLevel
              )}
            </div>
          </div>

          <div className="risk-status">
            <span>
              Confidence
            </span>

            <strong>
              {confidence.score ??
                confidence.confidence_score ??
                "N/A"}
            </strong>
          </div>
        </div>

        <div className="analysis-grid">
          <section className="panel">
            <div className="panel-header">
              <h3>
                Email Information
              </h3>
            </div>

            <div className="info-list">
              <div>
                <span>
                  From
                </span>

                <strong>
                  {email.from ||
                    "N/A"}
                </strong>
              </div>

              <div>
                <span>
                  To
                </span>

                <strong>
                  {email.to ||
                    "N/A"}
                </strong>
              </div>

              <div>
                <span>
                  Subject
                </span>

                <strong>
                  {email.subject ||
                    "N/A"}
                </strong>
              </div>

              <div>
                <span>
                  Reply-To
                </span>

                <strong>
                  {email.reply_to ||
                    "N/A"}
                </strong>
              </div>

              <div>
                <span>
                  Return-Path
                </span>

                <strong>
                  {email.return_path ||
                    "N/A"}
                </strong>
              </div>

              <div>
                <span>
                  Message-ID
                </span>

                <strong>
                  {email.message_id ||
                    "N/A"}
                </strong>
              </div>
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <h3>
                Email Authentication
              </h3>
            </div>

            <div className="auth-list">
              <div>
                <span>
                  SPF
                </span>

                {renderStatus(
                  auth.spf
                )}
              </div>

              <div>
                <span>
                  DKIM
                </span>

                {renderStatus(
                  auth.dkim
                )}
              </div>

              <div>
                <span>
                  DMARC
                </span>

                {renderStatus(
                  auth.dmarc
                )}
              </div>
            </div>
          </section>
        </div>

        <section className="panel threat-panel">
          <div className="panel-header">
            <div>
              <h3>
                Threat Indicators
              </h3>

              <p>
                Findings extracted from
                the actual uploaded email.
              </p>
            </div>
          </div>

          {indicators.length > 0 ? (
            <ul className="indicator-list">
              {indicators.map(
                (
                  indicator,
                  index
                ) => (
                  <li key={index}>
                    <span>
                      ⚠
                    </span>

                    <span>
                      {typeof indicator ===
                      "string"
                        ? indicator
                        : indicator?.description ||
                          indicator?.name ||
                          JSON.stringify(
                            indicator
                          )}
                    </span>
                  </li>
                )
              )}
            </ul>
          ) : (
            <div className="safe-message">
              ✓ No significant threat
              indicators detected.
            </div>
          )}
        </section>

        <div className="action-row">
          <button
            className="secondary-button"
            onClick={() =>
              setPage(
                "investigation"
              )
            }
          >
            View Investigation
          </button>

          <button
            className="secondary-button"
            onClick={() =>
              setPage("report")
            }
          >
            View Forensic Report
          </button>

          <button
            className="secondary-button"
            onClick={
              downloadJSON
            }
          >
            Download JSON
          </button>

          <button
            className="primary-button"
            onClick={
              generatePDF
            }
          >
            Generate PDF
          </button>

          <button
            className="secondary-button"
            onClick={
              resetAnalysis
            }
          >
            Analyze Another Email
          </button>
        </div>
      </>
    );
  };

  // ============================================================
  // INVESTIGATION
  // ============================================================

  const renderInvestigation = () => {
    if (!analysisResult) {
      return (
        <div className="empty-state">
          <h2>
            No Investigation Data
          </h2>

          <button
            className="primary-button"
            onClick={() =>
              setPage("upload")
            }
          >
            Analyze Email
          </button>
        </div>
      );
    }

    const originIP =
      ipAnalysis.candidate_origin_ip ||
      ipAnalysis.origin_ip ||
      "Not identified";

    const urlList =
      urls.urls ||
      urls.details ||
      [];

    return (
      <>
        <div className="page-heading">
          <h2>
            Forensic Investigation
          </h2>

          <p>
            Traceability and identity
            intelligence extracted from the
            uploaded email.
          </p>
        </div>

        <div className="investigation-grid">
          <section className="panel">
            <div className="panel-header">
              <h3>
                Origin IP
              </h3>
            </div>

            <div className="large-value">
              {originIP}
            </div>

            <p className="muted-text">
              Candidate originating IP
              extracted from the email route.
            </p>
          </section>

          <section className="panel">
            <div className="panel-header">
              <h3>
                Sender Identity
              </h3>
            </div>

            <div className="info-list">
              <div>
                <span>
                  Sender Domain
                </span>

                <strong>
                  {identity.sender_domain ||
                    email.sender_domain ||
                    "N/A"}
                </strong>
              </div>

              <div>
                <span>
                  Lookalike Domain
                </span>

                <strong>
                  {identity.lookalike_domain_detected
                    ? "Detected"
                    : "Not Detected"}
                </strong>
              </div>

              <div>
                <span>
                  Reply-To Mismatch
                </span>

                <strong>
                  {identity.reply_to_mismatch
                    ? "Detected"
                    : "No"}
                </strong>
              </div>

              <div>
                <span>
                  Return-Path Mismatch
                </span>

                <strong>
                  {identity.return_path_mismatch
                    ? "Detected"
                    : "No"}
                </strong>
              </div>

              <div>
                <span>
                  Message-ID Mismatch
                </span>

                <strong>
                  {identity.message_id_mismatch
                    ? "Detected"
                    : "No"}
                </strong>
              </div>
            </div>
          </section>
        </div>

        <section className="panel">
          <div className="panel-header">
            <h3>
              URL Intelligence
            </h3>
          </div>

          <div className="ioc-list">
            <div>
              <span>
                Total URLs
              </span>

              <strong>
                {urls.total_urls ??
                  0}
              </strong>
            </div>

            <div>
              <span>
                Suspicious URLs
              </span>

              <strong>
                {urls.suspicious_count ??
                  0}
              </strong>
            </div>
          </div>

          {Array.isArray(
            urlList
          ) && (
            <div className="url-table">
              {urlList.map(
                (
                  item,
                  index
                ) => (
                  <div
                    className="url-row"
                    key={index}
                  >
                    <span>
                      {index + 1}
                    </span>

                    <strong>
                      {typeof item ===
                      "string"
                        ? item
                        : item?.url ||
                          item?.domain ||
                          JSON.stringify(
                            item
                          )}
                    </strong>
                  </div>
                )
              )}
            </div>
          )}
        </section>

        <button
          className="primary-button"
          onClick={() =>
            setPage("report")
          }
        >
          Open Full Forensic Report
        </button>
      </>
    );
  };

  // ============================================================
  // FORENSIC REPORT
  // ============================================================

  const renderReport = () => {
    if (!analysisResult) {
      return (
        <div className="empty-state">
          <h2>
            No Forensic Report
          </h2>

          <button
            className="primary-button"
            onClick={() =>
              setPage("upload")
            }
          >
            Analyze Email
          </button>
        </div>
      );
    }

    return (
      <>
        <div className="page-heading">
          <h2>
            Forensic Report
          </h2>

          <p>
            Evidence-backed report generated
            from the actual email.
          </p>
        </div>

        <div className="report-actions">
          <button
            className="secondary-button"
            onClick={
              downloadJSON
            }
          >
            Download JSON
          </button>

          <button
            className="primary-button"
            onClick={
              generatePDF
            }
          >
            Generate PDF
          </button>
        </div>

        <div className="report-paper">
          <div className="report-heading">
            <h2>
              MAILTRACE
            </h2>

            <p>
              EMAIL FORENSIC ANALYSIS REPORT
            </p>
          </div>

          <div className="report-grid">
            <div>
              <span>
                Report ID
              </span>

              <strong>
                {analysisResult.report_id ||
                  "N/A"}
              </strong>
            </div>

            <div>
              <span>
                Analysis Version
              </span>

              <strong>
                {analysisResult.analysis_version ||
                  "N/A"}
              </strong>
            </div>

            <div>
              <span>
                Original File
              </span>

              <strong>
                {evidence.original_filename ||
                  "N/A"}
              </strong>
            </div>

            <div>
              <span>
                SHA-256
              </span>

              <strong>
                {evidence.sha256 ||
                  "N/A"}
              </strong>
            </div>
          </div>

          <hr />

          <h3>
            Threat Assessment
          </h3>

          <div className="report-grid">
            <div>
              <span>
                Risk Score
              </span>

              <strong>
                {riskScore}/100
              </strong>
            </div>

            <div>
              <span>
                Risk Level
              </span>

              <strong>
                {riskLevel}
              </strong>
            </div>

            <div>
              <span>
                Verdict
              </span>

              <strong>
                {verdict}
              </strong>
            </div>

            <div>
              <span>
                Confidence
              </span>

              <strong>
                {confidence.score ??
                  confidence.confidence_score ??
                  "N/A"}
              </strong>
            </div>
          </div>

          <hr />

          <h3>
            Email Details
          </h3>

          <div className="report-details">
            <p>
              <strong>
                From:
              </strong>{" "}
              {email.from ||
                "N/A"}
            </p>

            <p>
              <strong>
                To:
              </strong>{" "}
              {email.to ||
                "N/A"}
            </p>

            <p>
              <strong>
                Subject:
              </strong>{" "}
              {email.subject ||
                "N/A"}
            </p>

            <p>
              <strong>
                Reply-To:
              </strong>{" "}
              {email.reply_to ||
                "N/A"}
            </p>

            <p>
              <strong>
                Return-Path:
              </strong>{" "}
              {email.return_path ||
                "N/A"}
            </p>

            <p>
              <strong>
                Message-ID:
              </strong>{" "}
              {email.message_id ||
                "N/A"}
            </p>
          </div>

          <hr />

          <h3>
            Authentication Results
          </h3>

          <div className="auth-list">
            <div>
              <span>
                SPF
              </span>

              {renderStatus(
                auth.spf
              )}
            </div>

            <div>
              <span>
                DKIM
              </span>

              {renderStatus(
                auth.dkim
              )}
            </div>

            <div>
              <span>
                DMARC
              </span>

              {renderStatus(
                auth.dmarc
              )}
            </div>
          </div>

          <hr />

          <h3>
            Threat Indicators
          </h3>

          {indicators.length > 0 ? (
            <ul className="report-indicators">
              {indicators.map(
                (
                  indicator,
                  index
                ) => (
                  <li key={index}>
                    {typeof indicator ===
                    "string"
                      ? indicator
                      : indicator?.description ||
                        indicator?.name ||
                        JSON.stringify(
                          indicator
                        )}
                  </li>
                )
              )}
            </ul>
          ) : (
            <p>
              No significant threat
              indicators detected.
            </p>
          )}

          <hr />

          <h3>
            Evidence Preservation
          </h3>

          <p>
            Original filename:{" "}
            {evidence.original_filename ||
              "N/A"}
          </p>

          <p>
            SHA-256:{" "}
            {evidence.sha256 ||
              "N/A"}
          </p>

          <p>
            Chain of custody:{" "}
            {evidence.chain_of_custody ||
              "Evidence preserved for forensic analysis."}
          </p>
        </div>
      </>
    );
  };

  // ============================================================
  // VERIFICATION
  // ============================================================

  const renderVerification = () => (
    <>
      <div className="page-heading">
        <h2>
          Email Verification
        </h2>

        <p>
          SPF, DKIM and DMARC authentication
          results.
        </p>
      </div>

      {!analysisResult ? (
        <div className="empty-state">
          <h3>
            No email has been analyzed.
          </h3>

          <button
            className="primary-button"
            onClick={() =>
              setPage("upload")
            }
          >
            Analyze Email
          </button>
        </div>
      ) : (
        <section className="panel">
          <div className="verification-list">
            <div>
              <span>
                SPF
              </span>

              {renderStatus(
                auth.spf
              )}
            </div>

            <div>
              <span>
                DKIM
              </span>

              {renderStatus(
                auth.dkim
              )}
            </div>

            <div>
              <span>
                DMARC
              </span>

              {renderStatus(
                auth.dmarc
              )}
            </div>
          </div>
        </section>
      )}
    </>
  );

  // ============================================================
  // THREAT DETECTION
  // ============================================================

  const renderThreats = () => (
    <>
      <div className="page-heading">
        <h2>
          Threat Detection
        </h2>

        <p>
          Current email threat assessment.
        </p>
      </div>

      {!analysisResult ? (
        <div className="empty-state">
          <h3>
            No analysis available.
          </h3>

          <button
            className="primary-button"
            onClick={() =>
              setPage("upload")
            }
          >
            Analyze Email
          </button>
        </div>
      ) : (
        <>
          <div className="risk-summary">
            <div
              className={`risk-score ${getRiskClass()}`}
            >
              <span>
                Risk Score
              </span>

              <strong>
                {riskScore}
              </strong>

              <small>
                / 100
              </small>
            </div>

            <div className="risk-status">
              <span>
                Risk Level
              </span>

              <strong>
                {riskLevel}
              </strong>
            </div>

            <div className="risk-status">
              <span>
                Verdict
              </span>

              <strong>
                {verdict}
              </strong>
            </div>
          </div>

          <section className="panel">
            <div className="panel-header">
              <h3>
                Detected Indicators
              </h3>
            </div>

            {indicators.length ? (
              <ul className="indicator-list">
                {indicators.map(
                  (
                    item,
                    index
                  ) => (
                    <li key={index}>
                      ⚠{" "}
                      {typeof item ===
                      "string"
                        ? item
                        : item?.description ||
                          item?.name ||
                          JSON.stringify(
                            item
                          )}
                    </li>
                  )
                )}
              </ul>
            ) : (
              <div className="safe-message">
                ✓ No significant threat
                indicators detected.
              </div>
            )}
          </section>
        </>
      )}
    </>
  );

  // ============================================================
  // BLOCKCHAIN EVIDENCE
  // ============================================================

  const renderBlockchain = () => (
    <>
      <div className="page-heading">
        <h2>
          Blockchain Evidence
        </h2>

        <p>
          Evidence integrity and preservation.
        </p>
      </div>

      {!analysisResult ? (
        <div className="empty-state">
          <h3>
            No evidence available.
          </h3>

          <button
            className="primary-button"
            onClick={() =>
              setPage("upload")
            }
          >
            Analyze Email
          </button>
        </div>
      ) : (
        <section className="panel">
          <div className="info-list">
            <div>
              <span>
                Evidence File
              </span>

              <strong>
                {evidence.original_filename ||
                  selectedFile?.name ||
                  "N/A"}
              </strong>
            </div>

            <div>
              <span>
                SHA-256
              </span>

              <strong>
                {evidence.sha256 ||
                  "N/A"}
              </strong>
            </div>

            <div>
              <span>
                Chain of Custody
              </span>

              <strong>
                {evidence.chain_of_custody ||
                  "Evidence preserved during analysis."}
              </strong>
            </div>
          </div>
        </section>
      )}
    </>
  );

  // ============================================================
  // SETTINGS
  // ============================================================

  const renderSettings = () => (
    <>
      <div className="page-heading">
        <h2>
          Settings
        </h2>

        <p>
          Configure Mailtrace analysis
          preferences.
        </p>
      </div>

      <section className="panel settings-panel">
        <div className="setting-row">
          <div>
            <strong>
              Notifications
            </strong>

            <p>
              Receive analysis
              notifications.
            </p>
          </div>

          <input
            type="checkbox"
            checked={
              settings.notifications
            }
            onChange={(e) =>
              setSettings({
                ...settings,
                notifications:
                  e.target.checked,
              })
            }
          />
        </div>

        <div className="setting-row">
          <div>
            <strong>
              Automatic Analysis
            </strong>

            <p>
              Automatically process
              selected evidence.
            </p>
          </div>

          <input
            type="checkbox"
            checked={
              settings.autoAnalysis
            }
            onChange={(e) =>
              setSettings({
                ...settings,
                autoAnalysis:
                  e.target.checked,
              })
            }
          />
        </div>

        <div className="setting-row">
          <div>
            <strong>
              Evidence Protection
            </strong>

            <p>
              Preserve uploaded
              evidence hashes.
            </p>
          </div>

          <input
            type="checkbox"
            checked={
              settings.evidenceProtection
            }
            onChange={(e) =>
              setSettings({
                ...settings,
                evidenceProtection:
                  e.target.checked,
              })
            }
          />
        </div>
      </section>
    </>
  );

  // ============================================================
  // PAGE ROUTER
  // ============================================================

  const renderPage = () => {
    switch (page) {
      case "overview":
        return renderOverview();

      case "threats":
        return renderThreats();

      case "verification":
        return renderVerification();

      case "blockchain":
        return renderBlockchain();

      case "upload":
        return renderUpload();

      case "analysis":
        return renderAnalysis();

      case "investigation":
        return renderInvestigation();

      case "report":
        return renderReport();

      case "settings":
        return renderSettings();

      default:
        return renderOverview();
    }
  };

  // ============================================================
  // MAIN APP
  // ============================================================

  return (
    <div className="app">
      {renderSidebar()}

      <main className="main-content">
        {renderTopbar()}

        <div className="content-area">
          {renderPage()}
        </div>
      </main>
    </div>
  );
}


export default App;

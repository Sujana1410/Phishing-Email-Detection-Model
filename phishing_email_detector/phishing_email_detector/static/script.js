const emailText = document.getElementById("emailText");
const classifyBtn = document.getElementById("classifyBtn");
const sampleBtn = document.getElementById("sampleBtn");
const sampleSafeBtn = document.getElementById("sampleSafeBtn");
const resultBox = document.getElementById("resultBox");

const PHISHING_SAMPLE = `Subject: Your account has been suspended
From: security-alert@secure-login-verify.com

Dear Customer,

Your account has been suspended due to unusual activity. Click here immediately to verify your account: http://secure-login-verify.com/verify?user=482913

Failure to act within 24 hours will result in permanent suspension.

Security Team`;

const SAFE_SAMPLE = `Subject: Meeting rescheduled to next week
From: priya@company.com

Hi Alex,

Just a reminder that our meeting has been moved to Wednesday at 2:00 PM. Let me know if that works for you.

Best,
Priya`;

sampleBtn.addEventListener("click", () => {
  emailText.value = PHISHING_SAMPLE;
});

sampleSafeBtn.addEventListener("click", () => {
  emailText.value = SAFE_SAMPLE;
});

classifyBtn.addEventListener("click", async () => {
  const text = emailText.value.trim();
  if (!text) {
    showError("Please paste some email text first.");
    return;
  }

  classifyBtn.disabled = true;
  classifyBtn.textContent = "Analyzing...";

  try {
    const res = await fetch("/api/classify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text }),
    });
    const data = await res.json();

    if (!res.ok) {
      showError(data.error || "Classification failed.");
      return;
    }
    renderResult(data);
  } catch (err) {
    showError("Error contacting server. Is the Flask app running?");
  } finally {
    classifyBtn.disabled = false;
    classifyBtn.textContent = "Classify Email";
  }
});

function showError(msg) {
  resultBox.style.display = "block";
  resultBox.className = "result-box";
  resultBox.innerHTML = `<div style="color:#ff4d4f">${escapeHtml(msg)}</div>`;
}

function renderResult(data) {
  resultBox.style.display = "block";
  resultBox.className = "result-box " + (data.is_phishing ? "phishing" : "safe");

  const barColor = data.is_phishing ? "#ff4d4f" : "#4cd97b";
  const confidencePct = Math.round(data.confidence * 100);

  let html = `
    <div class="result-label ${data.is_phishing ? "phishing" : "safe"}">
      ${data.is_phishing ? "⚠️ Phishing Detected" : "✅ Looks Safe"}
    </div>
    <div>Confidence: ${confidencePct}%</div>
    <div class="confidence-bar-container">
      <div class="confidence-bar-fill" style="width:${confidencePct}%; background:${barColor};"></div>
    </div>
    <div class="muted">P(phishing) = ${(data.probability_phishing * 100).toFixed(1)}% &nbsp;|&nbsp; P(safe) = ${(data.probability_safe * 100).toFixed(1)}%</div>
    <div class="feature-grid">
  `;

  const labels = {
    url_count: "URLs found",
    has_ip_url: "IP-based URL",
    suspicious_keyword_count: "Suspicious keywords",
    sensitive_request_count: "Sensitive-data requests",
    exclamation_count: "Exclamation marks",
    uppercase_ratio: "Uppercase ratio",
    text_length: "Text length (chars)",
  };

  for (const [key, value] of Object.entries(data.feature_breakdown)) {
    html += `<div class="feature-item">${labels[key] || key}: <strong>${value}</strong></div>`;
  }
  html += `</div>`;

  resultBox.innerHTML = html;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

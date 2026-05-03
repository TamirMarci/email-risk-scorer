const API_URL = "http://localhost:8000/analyze-email";

const analyzeBtn = document.getElementById("analyzeBtn");
const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const scoreEl = document.getElementById("score");
const verdictEl = document.getElementById("verdict");
const recommendationEl = document.getElementById("recommendation");
const reasonsEl = document.getElementById("reasons");
const trustSectionEl = document.getElementById("trust-section");
const trustSignalsEl = document.getElementById("trust-signals");
const needleEl = document.getElementById("gauge-needle");
const actionsSectionEl = document.getElementById("actions-section");
const actionsListEl = document.getElementById("actions-list");
const scoreAdjustmentEl = document.getElementById("score-adjustment");

function extractEmailFromGmailPage() {
  const subject = document.querySelector("h2.hP")?.innerText?.trim() || "";

  const senderNode = document.querySelector("span[email]");
  const sender = senderNode?.getAttribute("email") || senderNode?.innerText || "";

  const bodyNodes = Array.from(document.querySelectorAll("div.a3s.aiL, div.a3s"));
  const body = bodyNodes.map(node => node.innerText || "").join("\n").slice(0, 20000);

  const links = Array.from(document.querySelectorAll("div.a3s a[href], div.aiL a[href]"))
    .map(a => a.href)
    .filter(Boolean)
    .slice(0, 100);

  return { subject, sender, body, links };
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

const VERDICT_CLASSES = ["verdict-very-low", "verdict-low", "verdict-medium", "verdict-high", "verdict-critical"];

function renderResult(data) {
  resultEl.hidden = false;

  // Needle: score 0 → -90°, score 100 → +90°
  needleEl.setAttribute("transform", `rotate(${(data.score / 100) * 180 - 90} 110 110)`);

  scoreEl.textContent = data.score;
  verdictEl.textContent = data.verdict;
  VERDICT_CLASSES.forEach(c => verdictEl.classList.remove(c));
  const cls = "verdict-" + data.verdict.toLowerCase().replace(" ", "-");
  verdictEl.classList.add(cls);
  recommendationEl.textContent = data.recommendation;
  scoreAdjustmentEl.hidden = true;
  scoreAdjustmentEl.textContent = "";
  reasonsEl.innerHTML = "";
  trustSignalsEl.innerHTML = "";
  trustSectionEl.hidden = true;
  actionsListEl.innerHTML = "";
  actionsSectionEl.hidden = true;

  if (data.score_adjustments && data.score_adjustments.length > 0) {
    const adj = data.score_adjustments[0];
    scoreAdjustmentEl.hidden = false;
    scoreAdjustmentEl.textContent =
      `Base score: ${data.raw_score} → adjusted to ${data.score}: ${adj.reason}`;
  }

  if (data.actions && data.actions.length > 0) {
    actionsSectionEl.hidden = false;
    data.actions.forEach(action => {
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = action.title;
      details.appendChild(summary);
      const ol = document.createElement("ol");
      action.steps.forEach(step => {
        const li = document.createElement("li");
        li.textContent = step;
        ol.appendChild(li);
      });
      details.appendChild(ol);
      actionsListEl.appendChild(details);
    });
  }

  if (!data.reasons || data.reasons.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No strong malicious indicators found.";
    reasonsEl.appendChild(li);
  } else {
    data.reasons.forEach(reason => {
      const pct = reason.confidence != null ? ` <span class="confidence">${Math.round(reason.confidence * 100)}%</span>` : "";
      const contrib = reason.contribution != null ? ` <span class="contribution">+${reason.contribution}pts</span>` : "";
      const li = document.createElement("li");
      li.innerHTML = `<span class="badge">${reason.severity}</span>${pct}${contrib} · ${reason.signal}: ${reason.explanation}`;
      reasonsEl.appendChild(li);
    });
  }

  if (data.trust_signals && data.trust_signals.length > 0) {
    trustSectionEl.hidden = false;
    data.trust_signals.forEach(ts => {
      const li = document.createElement("li");
      li.innerHTML = `<span class="badge trust">trust</span> · ${ts.signal}: ${ts.explanation}`;
      trustSignalsEl.appendChild(li);
    });
  }
}

analyzeBtn.addEventListener("click", async () => {
  analyzeBtn.disabled = true;
  statusEl.textContent = "Analyzing...";
  resultEl.hidden = true;

  try {
    const tab = await getActiveTab();
    if (!tab.url || !tab.url.includes("mail.google.com")) {
      throw new Error("Please open Gmail and select an email first.");
    }

    const [{ result: emailData }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: extractEmailFromGmailPage
    });

    if (!emailData.subject && !emailData.body) {
      throw new Error("Could not read email content. Make sure a Gmail message is open.");
    }

    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(emailData)
    });

    if (!response.ok) {
      throw new Error(`Backend error: ${response.status}`);
    }

    const data = await response.json();
    statusEl.textContent = `Analyzed: ${emailData.subject || "current email"}`;
    renderResult(data);
  } catch (error) {
    statusEl.textContent = error.message;
  } finally {
    analyzeBtn.disabled = false;
  }
});

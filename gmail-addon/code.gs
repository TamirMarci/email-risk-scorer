const BACKEND_URL = "https://unmoving-frugally-subheader.ngrok-free.dev/analyze-email";

function onGmailMessageOpen(e) {
  try {
    const accessToken = e.gmail.accessToken;
    GmailApp.setCurrentMessageAccessToken(accessToken);

    const messageId = e.gmail.messageId;
    const message = GmailApp.getMessageById(messageId);

    const subject = message.getSubject() || "";
    const sender = message.getFrom() || "";
    const htmlBody = message.getBody() || "";
    const body = stripHtml(htmlBody);
    const links = extractLinks(htmlBody);

    const result = analyzeEmail({
      subject: subject,
      sender: sender,
      body: body,
      links: links
    });

    return buildResultCard(subject, result);

  } catch (err) {
    return buildErrorCard(err);
  }
}

function analyzeEmail(payload) {
  const response = UrlFetchApp.fetch(BACKEND_URL, {
    method: "post",
    contentType: "application/json",
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  });

  const status = response.getResponseCode();
  const text = response.getContentText();

  if (status >= 400) {
    throw new Error("Backend returned HTTP " + status + ": " + text);
  }

  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error("Backend did not return JSON. Response was: " + text);
  }
}

function stripHtml(html) {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractLinks(html) {
  const links = [];
  const regex = /href=["']([^"']+)["']/gi;
  let match;

  while ((match = regex.exec(html)) !== null) {
    links.push(match[1]);
  }

  return links;
}

function buildResultCard(subject, result) {
  const score = result.score || 0;
  const rawScore = result.raw_score;
  const verdict = result.verdict || "Unknown";
  const recommendation = result.recommendation || "";
  const reasons = result.reasons || [];
  const trustSignals = result.trust_signals || [];
  const adjustments = result.score_adjustments || [];
  const actions = result.actions || [];

  const badge = getVerdictBadge(verdict);

  const card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Risk Scorer")
        .setSubtitle(badge + " " + verdict + " · Score " + score + "/100")
    );

  const summaryText =
    "<b>Risk Assessment</b><br>" +
    "<font color=\"" + getVerdictColor(verdict) + "\"><b>" +
    badge + " " + verdict + " · " + score + "/100</b></font><br>" +
    (rawScore !== undefined ? "Base score: " + rawScore + "<br>" : "") +
    "<br><b>Recommendation</b><br>" +
    escapeHtml(recommendation);

  card.addSection(
    CardService.newCardSection()
      .setHeader("Summary")
      .addWidget(CardService.newTextParagraph().setText(summaryText))
  );

  card.addSection(
    CardService.newCardSection()
      .setHeader("Email")
      .addWidget(
        CardService.newTextParagraph()
          .setText("<b>Subject:</b><br>" + escapeHtml(subject))
      )
  );

  if (reasons.length > 0) {
    const riskSection = CardService.newCardSection().setHeader("Risk Indicators");

    reasons.slice(0, 6).forEach(function(reason) {
      riskSection.addWidget(
        CardService.newTextParagraph()
          .setText(
            "<b>" + escapeHtml((reason.severity || "").toUpperCase()) +
            " · +" + escapeHtml(reason.contribution || 0) + " pts</b><br>" +
            escapeHtml(reason.signal || "Signal") + "<br>" +
            "<font color=\"#5F6368\">" + escapeHtml(reason.explanation || "") + "</font>"
          )
      );
    });

    card.addSection(riskSection);
  } else {
    card.addSection(
      CardService.newCardSection()
        .setHeader("Risk Indicators")
        .addWidget(
          CardService.newTextParagraph()
            .setText("No meaningful risk indicators were detected.")
        )
    );
  }

  if (trustSignals.length > 0) {
    const trustSection = CardService.newCardSection().setHeader("Trust Signals");

    trustSignals.slice(0, 6).forEach(function(signal) {
      trustSection.addWidget(
        CardService.newTextParagraph()
          .setText(
            "<b>TRUST · -" + escapeHtml(signal.points_reduction || 0) + " pts</b><br>" +
            escapeHtml(signal.signal || "Trust signal") + "<br>" +
            "<font color=\"#5F6368\">" + escapeHtml(signal.explanation || "") + "</font>"
          )
      );
    });

    card.addSection(trustSection);
  }

  if (adjustments.length > 0) {
    const adjustmentSection = CardService.newCardSection().setHeader("Score Transparency");

    adjustments.slice(0, 3).forEach(function(adj) {
      adjustmentSection.addWidget(
        CardService.newTextParagraph()
          .setText(
            "<b>" + escapeHtml(adj.type || "adjustment") + "</b><br>" +
            escapeHtml(adj.reason || "Score adjusted") +
            "<br>" + escapeHtml(adj.from_score) + " → " + escapeHtml(adj.to_score)
          )
      );
    });

    card.addSection(adjustmentSection);
  }

  if (actions.length > 0) {
    const actionsSection = CardService.newCardSection().setHeader("Recommended Actions");

    actions.forEach(function(action) {
      actionsSection.addWidget(
        CardService.newTextParagraph()
          .setText(
            "<b>" + escapeHtml(action.title || "Action") + "</b><br>" +
            (action.steps || []).map(escapeHtml).join("<br>")
          )
      );
    });

    card.addSection(actionsSection);
  }

  card.addSection(
    CardService.newCardSection()
      .setHeader("Disclaimer")
      .addWidget(
        CardService.newTextParagraph()
          .setText("This tool provides heuristic risk estimation and is not definitive.")
      )
  );

  return card.build();
}

function getVerdictBadge(verdict) {
  if (verdict === "Critical") return "🔴";
  if (verdict === "High") return "🟠";
  if (verdict === "Medium") return "🟡";
  if (verdict === "Low") return "🟢";
  if (verdict === "Very Low") return "✅";
  return "⚪";
}

function getVerdictColor(verdict) {
  if (verdict === "Critical") return "#D93025";
  if (verdict === "High") return "#E8710A";
  if (verdict === "Medium") return "#F9AB00";
  if (verdict === "Low") return "#188038";
  if (verdict === "Very Low") return "#188038";
  return "#5F6368";
}

function buildErrorCard(err) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Risk Scorer")
        .setSubtitle("Analysis failed")
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText(escapeHtml(err.message || String(err)))
        )
    )
    .build();
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}
(async function () {
  const statusEl = document.getElementById("status");
  const statusText = document.getElementById("status-text");
  const listEl = document.getElementById("flag-list");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) {
    statusText.textContent = "No active tab.";
    return;
  }

  const key = `report_${tab.id}`;
  const stored = await chrome.storage.local.get(key);
  const report = stored[key];

  if (!report || !report.flags || report.flags.length === 0) {
    statusEl.className = "status status--safe";
    statusText.textContent = "No phishing indicators found on this page.";
    return;
  }

  statusEl.className =
    report.riskScore === "high" ? "status status--high" : "status status--medium";
  statusText.textContent =
    report.riskScore === "high"
      ? `\u26A0\uFE0F High risk \u2014 ${report.flags.length} issue(s) found`
      : `${report.flags.length} issue(s) found \u2014 review before proceeding`;

  report.flags.forEach((flag) => {
    const li = document.createElement("li");
    li.className = flag.severity;
    li.textContent = flag.message;
    listEl.appendChild(li);
  });
})();

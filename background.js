/**
 * background.js (service worker)
 * Only the background script can see the full navigation/redirect history
 * of a tab via chrome.webNavigation — content scripts can't. It:
 *   1. Tracks the redirect chain for each tab's main-frame navigation
 *   2. Flags chains that are long or hop across many unrelated domains
 *   3. Relays page risk reports from content.js into per-tab storage
 *   4. Sets the toolbar badge so risk is visible at a glance
 */

const KNOWN_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"
];

// tabId -> [{url, timestamp}]
const redirectChains = new Map();

function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return "";
  }
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return; // main frame only
  redirectChains.set(details.tabId, [{ url: details.url, t: Date.now() }]);
});

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  const chain = redirectChains.get(details.tabId) || [];
  const isRedirect =
    details.transitionQualifiers &&
    (details.transitionQualifiers.includes("server_redirect") ||
      details.transitionQualifiers.includes("client_redirect"));

  if (isRedirect) {
    chain.push({ url: details.url, t: Date.now() });
    redirectChains.set(details.tabId, chain);
  }
});

chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  const chain = redirectChains.get(details.tabId) || [];
  if (chain.length === 0) return;

  const hosts = chain.map((step) => hostnameOf(step.url));
  const uniqueHosts = new Set(hosts);
  const usedShortener = hosts.some((h) =>
    KNOWN_SHORTENERS.some((s) => h === s || h.endsWith("." + s))
  );

  let message = null;
  if (uniqueHosts.size >= 3) {
    message = `This page was reached through ${uniqueHosts.size} different domains before landing here (${[...uniqueHosts].join(" \u2192 ")}).`;
  } else if (usedShortener) {
    message = "This page was reached through a URL shortener, which can hide the real destination.";
  }

  if (message) {
    chrome.tabs
      .sendMessage(details.tabId, { type: "redirect-warning", message })
      .catch(() => {
        /* content script may not be injected on this page (e.g. chrome:// pages) */
      });
  }
});

chrome.webNavigation.onErrorOccurred.addListener((details) => {
  if (details.frameId === 0) redirectChains.delete(details.tabId);
});

// ---------------------------------------------------------------------
// Receive risk reports from content.js, store per tab, update badge
// ---------------------------------------------------------------------
chrome.runtime.onMessage.addListener((message, sender) => {
  if (message?.type !== "page-risk-report" || !sender.tab) return;

  const tabId = sender.tab.id;
  chrome.storage.local.set({
    [`report_${tabId}`]: {
      url: message.url,
      riskScore: message.riskScore,
      flags: message.flags,
      updatedAt: Date.now(),
    },
  });

  const isHigh = message.riskScore === "high";
  chrome.action.setBadgeText({ tabId, text: isHigh ? "!" : "\u2022" });
  chrome.action.setBadgeBackgroundColor({
    tabId,
    color: isHigh ? "#b91c1c" : "#d97706",
  });
});

// Clear the badge and stored report when a tab navigates to a new page
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  chrome.action.setBadgeText({ tabId: details.tabId, text: "" });
  chrome.storage.local.remove(`report_${details.tabId}`);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  redirectChains.delete(tabId);
  chrome.storage.local.remove(`report_${tabId}`);
});

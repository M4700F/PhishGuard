/**
 * content.js
 * Runs in an ISOLATED world (can't be touched by the page's own JS, but can
 * read/modify the DOM). Responsible for:
 *   1. Lookalike / typosquat domain detection
 *   2. Inspecting <form> elements that collect passwords
 *   3. Listening for credential-exfiltration signals from inject.js
 *      (which runs in the page's MAIN world and hooks fetch/XHR)
 *   4. Rendering a warning banner and reporting a risk score to the
 *      background service worker (for the toolbar badge + popup).
 */

(function () {
  "use strict";

  // ---------------------------------------------------------------------
  // 1. Known brand domains commonly targeted by phishing.
  //    In a real product you'd pull this from a maintained list/service
  //    instead of hardcoding it.
  // ---------------------------------------------------------------------
  const KNOWN_BRANDS = [
    "paypal.com", "google.com", "facebook.com", "apple.com", "microsoft.com",
    "amazon.com", "netflix.com", "instagram.com", "linkedin.com", "chase.com",
    "bankofamerica.com", "wellsfargo.com", "dropbox.com", "github.com",
    "outlook.com", "yahoo.com", "adobe.com", "steamcommunity.com", "coinbase.com"
  ];

  const flags = []; // collected {severity, message} for this page

  // ---------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------

  // Classic Levenshtein edit distance (small strings, so O(n*m) is fine)
  function levenshtein(a, b) {
    const dp = Array.from({ length: a.length + 1 }, (_, i) =>
      new Array(b.length + 1).fill(0)
    );
    for (let i = 0; i <= a.length; i++) dp[i][0] = i;
    for (let j = 0; j <= b.length; j++) dp[0][j] = j;
    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        dp[i][j] =
          a[i - 1] === b[j - 1]
            ? dp[i - 1][j - 1]
            : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
    return dp[a.length][b.length];
  }

  // Naive "registrable domain" extraction (last two labels).
  // NOTE: this breaks for multi-part TLDs like .co.uk / .com.bd.
  // For production, use a Public Suffix List library instead.
  function registrableDomain(hostname) {
    const parts = hostname.split(".");
    return parts.length >= 2 ? parts.slice(-2).join(".") : hostname;
  }

  function addFlag(severity, message) {
    flags.push({ severity, message });
  }

  // ---------------------------------------------------------------------
  // 2. Lookalike domain detection
  // ---------------------------------------------------------------------
  function checkLookalikeDomain() {
    const host = window.location.hostname.toLowerCase();
    const reg = registrableDomain(host);
    const regRoot = reg.split(".")[0];

    for (const brand of KNOWN_BRANDS) {
      if (reg === brand) return; // exact legitimate match, nothing to flag

      const brandRoot = brand.split(".")[0];

      // Brand name embedded as a subdomain trick, e.g. paypal.com.evil.co
      // or secure-paypal-login.com
      if (host.includes(brandRoot) && reg !== brand) {
        addFlag(
          "high",
          `Page hostname contains "${brandRoot}" but the actual domain is "${reg}", not "${brand}".`
        );
        continue;
      }

      // Near-miss typosquat, e.g. paypa1.com, paypal-secure.com root
      if (regRoot.length >= 4) {
        const dist = levenshtein(regRoot, brandRoot);
        if (dist > 0 && dist <= 2) {
          addFlag(
            "medium",
            `Domain "${reg}" is suspiciously close (edit distance ${dist}) to "${brand}".`
          );
        }
      }
    }
  }

  // ---------------------------------------------------------------------
  // 3. Forms that collect a password and submit somewhere unexpected
  // ---------------------------------------------------------------------
  function checkForms() {
    const forms = document.querySelectorAll("form");
    forms.forEach((form) => {
      const hasPassword = !!form.querySelector('input[type="password"]');
      if (!hasPassword) return;

      let actionUrl;
      try {
        actionUrl = new URL(form.getAttribute("action") || window.location.href, window.location.href);
      } catch (e) {
        return;
      }

      if (actionUrl.hostname !== window.location.hostname) {
        addFlag(
          "high",
          `A form with a password field submits to a different domain: ${actionUrl.hostname}`
        );
      }

      // Re-check at the moment of submission too, in case JS rewrote
      // the action attribute after page load.
      form.addEventListener(
        "submit",
        () => {
          let liveAction;
          try {
            liveAction = new URL(form.action, window.location.href);
          } catch (e) {
            return;
          }
          if (liveAction.hostname !== window.location.hostname) {
            showBanner([
              `Blocked-warning: this form is about to send credentials to ${liveAction.hostname}, a different domain than ${window.location.hostname}.`,
            ]);
          }
        },
        { capture: true }
      );
    });
  }

  // ---------------------------------------------------------------------
  // 4. Signals from inject.js (MAIN world fetch/XHR hooks)
  // ---------------------------------------------------------------------
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== "phishguard") return;

    if (data.type === "suspicious-fetch") {
      let host = "unknown";
      try {
        host = new URL(data.url, window.location.href).hostname;
      } catch (e) {}
      addFlag(
        "high",
        `A script sent what looks like a password value to ${host} via ${data.method || "fetch/XHR"}.`
      );
      renderAndReport();
    }
  });

  // ---------------------------------------------------------------------
  // Redirect-chain info comes from the background service worker
  // (only it can see the full navigation/redirect history via webNavigation).
  // ---------------------------------------------------------------------
  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === "redirect-warning") {
      addFlag("medium", msg.message);
      renderAndReport();
    }
  });

  // ---------------------------------------------------------------------
  // UI: a small dismissible banner injected at the top of the page
  // ---------------------------------------------------------------------
  let bannerShown = false;
  function showBanner(messages) {
    if (bannerShown) return;
    bannerShown = true;

    const bar = document.createElement("div");
    bar.setAttribute("id", "phishguard-banner");
    bar.style.cssText = [
      "position:fixed", "top:0", "left:0", "right:0", "z-index:2147483647",
      "background:#b91c1c", "color:#fff", "font-family:system-ui,sans-serif",
      "font-size:14px", "padding:10px 16px", "display:flex",
      "justify-content:space-between", "align-items:center",
      "box-shadow:0 2px 6px rgba(0,0,0,.3)"
    ].join(";");

    const text = document.createElement("span");
    text.textContent = "\u26A0\uFE0F PhishGuard: " + messages.join(" ");
    bar.appendChild(text);

    const close = document.createElement("button");
    close.textContent = "Dismiss";
    close.style.cssText =
      "margin-left:12px;background:#fff;color:#b91c1c;border:none;border-radius:4px;padding:4px 10px;cursor:pointer;font-weight:600;";
    close.onclick = () => bar.remove();
    bar.appendChild(close);

    document.documentElement.appendChild(bar);
  }

  // ---------------------------------------------------------------------
  // Aggregate risk + report to background (for badge) and popup (via storage)
  // ---------------------------------------------------------------------
  function renderAndReport() {
    if (flags.length === 0) return;

    const highCount = flags.filter((f) => f.severity === "high").length;
    const riskScore = highCount > 0 ? "high" : "medium";

    showBanner(flags.map((f) => f.message));

    chrome.runtime.sendMessage({
      type: "page-risk-report",
      url: window.location.href,
      riskScore,
      flags,
    });
  }

  // ---------------------------------------------------------------------
  // Run checks once the DOM is ready
  // ---------------------------------------------------------------------
  function run() {
    checkLookalikeDomain();
    checkForms();
    renderAndReport();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", run);
  } else {
    run();
  }
})();

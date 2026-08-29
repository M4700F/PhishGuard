/**
 * inject.js
 * Runs in the page's MAIN world (declared via "world": "MAIN" in the
 * manifest), so it can see and patch the page's own window.fetch /
 * XMLHttpRequest. This is how we catch phishing pages that steal
 * credentials via JS instead of a plain HTML form submission.
 *
 * It never reads password values itself except to compare them against
 * outgoing request bodies, and only reports "this looked like a password
 * was sent" back to content.js — never the value itself.
 */
(function () {
  "use strict";

  function currentPasswordValues() {
    return Array.from(document.querySelectorAll('input[type="password"]'))
      .map((el) => el.value)
      .filter((v) => v && v.length >= 4);
  }

  function bodyContainsPassword(body) {
    if (!body) return false;
    let text;
    try {
      text = typeof body === "string" ? body : JSON.stringify(body);
    } catch (e) {
      return false;
    }
    return currentPasswordValues().some((pw) => text.includes(pw));
  }

  function report(url, method) {
    window.postMessage(
      { source: "phishguard", type: "suspicious-fetch", url, method },
      "*"
    );
  }

  // --- Hook fetch ---
  const originalFetch = window.fetch;
  window.fetch = function (input, init) {
    try {
      const url = typeof input === "string" ? input : input && input.url;
      const body = init && init.body;
      if (bodyContainsPassword(body)) {
        report(url, "fetch");
      }
    } catch (e) {
      /* never let our instrumentation break the page */
    }
    return originalFetch.apply(this, arguments);
  };

  // --- Hook XMLHttpRequest ---
  const originalOpen = XMLHttpRequest.prototype.open;
  const originalSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function (method, url) {
    this.__phishguard_url = url;
    return originalOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function (body) {
    try {
      if (bodyContainsPassword(body)) {
        report(this.__phishguard_url, "XHR");
      }
    } catch (e) {
      /* ignore */
    }
    return originalSend.apply(this, arguments);
  };
})();

let currentOrigin = "";
let enabled = false;

document.addEventListener("DOMContentLoaded", () => {
  bind("toggle-origin", toggleOrigin);
  bind("collect", collectNow);
  bind("export", exportReceipts);
  bind("native", forwardToNative);
  document
    .getElementById("capture-snapshots")
    .addEventListener("change", toggleCaptureSnapshots);
  refresh().catch(showError);
});

function bind(id, handler) {
  document.getElementById(id).addEventListener("click", () => {
    handler().catch(showError);
  });
}

async function refresh() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  currentOrigin = normalizeOrigin(tab?.url || "");
  const state = await chrome.runtime.sendMessage({
    type: "ardur.personal.get_state",
    origin: currentOrigin
  });
  if (!state.ok) {
    throw new Error(state.error || "state unavailable");
  }
  enabled = Boolean(state.enabled);
  renderState(state);
}

function renderState(state) {
  document.getElementById("origin").textContent = state.origin || "-";
  const toggle = document.getElementById("toggle-origin");
  toggle.textContent = state.enabled ? "Disable" : "Enable";
  toggle.dataset.enabled = String(state.enabled);
  document.getElementById("collect").disabled = !state.enabled;
  const capture = document.getElementById("capture-snapshots");
  capture.checked = Boolean(state.captureSnapshots);
  capture.disabled = !state.enabled;
  document.getElementById("capture-mode").textContent = state.captureSnapshots
    ? "Review text"
    : "Digest only";
  document.getElementById("count").textContent = String(state.receipts.length);
  const timeline = document.getElementById("timeline");
  timeline.replaceChildren(...state.receipts.map(receiptItem));
  renderReview(state.latestReview);
}

function receiptItem(receipt) {
  const item = document.createElement("li");
  const head = document.createElement("div");
  head.className = "receipt-head";

  const id = document.createElement("span");
  id.className = "receipt-id";
  id.textContent = receipt.receipt_id.slice(0, 8);

  const verdict = document.createElement("span");
  verdict.className = `verdict ${receipt.policy.verdict}`;
  verdict.textContent = receipt.policy.verdict;

  const target = document.createElement("p");
  target.textContent = receipt.event.target;

  const digest = document.createElement("p");
  digest.className = "digest";
  digest.textContent = receipt.event.content_digest.slice(0, 24);

  head.append(id, verdict);
  item.append(head, target, digest);
  return item;
}

function renderReview(review) {
  document.getElementById("review-provider").textContent = review?.provider || "-";
  document.getElementById("review-summary").textContent = review?.summary || "No review yet.";
  const labels = document.getElementById("review-labels");
  labels.replaceChildren(...(review?.policy_labels || []).map(labelItem));
  const actions = document.getElementById("actions");
  actions.replaceChildren(...(review?.actions || []).slice(-5).reverse().map(actionItem));
}

function labelItem(value) {
  const item = document.createElement("span");
  item.className = `policy-label ${value}`;
  item.textContent = value;
  return item;
}

function actionItem(action) {
  const item = document.createElement("li");
  item.className = "action";

  const head = document.createElement("div");
  head.className = "receipt-head";

  const kind = document.createElement("span");
  kind.className = "action-kind";
  kind.textContent = action.kind.replace(/_/g, " ");

  const labels = document.createElement("span");
  labels.className = "digest";
  labels.textContent = action.policy_labels.join(", ");

  const summary = document.createElement("p");
  summary.textContent = action.summary;

  head.append(kind, labels);
  item.append(head, summary);
  return item;
}

async function toggleOrigin() {
  if (!currentOrigin) {
    throw new Error("current site is unavailable");
  }
  if (enabled) {
    await chrome.runtime.sendMessage({
      type: "ardur.personal.disable_origin",
      origin: currentOrigin
    });
    await refresh();
    setStatus("Disabled");
    return;
  }
  const granted = await chrome.permissions.request({
    origins: [`${currentOrigin}/*`]
  });
  if (!granted) {
    setStatus("Not enabled");
    return;
  }
  await chrome.runtime.sendMessage({
    type: "ardur.personal.enable_origin",
    origin: currentOrigin
  });
  await injectContentScript();
  await refresh();
  setStatus("Enabled");
}

async function toggleCaptureSnapshots(event) {
  if (!currentOrigin || !enabled) {
    event.target.checked = false;
    throw new Error("enable the site first");
  }
  const response = await chrome.runtime.sendMessage({
    type: "ardur.personal.set_capture_snapshots",
    origin: currentOrigin,
    enabled: event.target.checked
  });
  if (!response.ok) {
    throw new Error(response.error || "capture setting failed");
  }
  await refresh();
  setStatus(event.target.checked ? "Review text on" : "Digest only");
}

async function collectNow() {
  await injectContentScript();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  await chrome.tabs.sendMessage(tab.id, { type: "ardur.personal.collect_now" });
  setTimeout(() => refresh().catch(showError), 500);
}

async function injectContentScript() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    throw new Error("active tab unavailable");
  }
  await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    files: ["src/content_script.js"]
  });
}

async function exportReceipts() {
  const exported = await chrome.runtime.sendMessage({
    type: "ardur.personal.export_receipts"
  });
  if (!exported.ok) {
    throw new Error(exported.error || "export failed");
  }
  const blob = new Blob([JSON.stringify(exported, null, 2)], {
    type: "application/json"
  });
  const url = URL.createObjectURL(blob);
  await chrome.tabs.create({ url });
}

async function forwardToNative() {
  const hasPermission = await chrome.permissions.request({
    permissions: ["nativeMessaging"]
  });
  if (!hasPermission) {
    setStatus("Host off");
    return;
  }
  const response = await chrome.runtime.sendMessage({
    type: "ardur.personal.forward_to_native"
  });
  if (!response.ok) {
    throw new Error(response.error || "host unavailable");
  }
  setStatus("Forwarded");
}

function normalizeOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}

function setStatus(value) {
  document.getElementById("status").textContent = value;
}

function showError(error) {
  setStatus(error.message || String(error));
}

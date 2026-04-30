const EVENT_TYPE = "ardur.observed_event.v0.1";
const RECEIPT_TYPE = "ardur.personal.browser_receipt.v0.1";
const SETTINGS_KEY = "ardur_personal_settings";
const RECEIPTS_KEY = "ardur_personal_receipts";
const SESSION_REVIEWS_KEY = "ardur_personal_session_reviews";
const MAX_RECEIPTS = 500;
const MAX_SESSION_REVIEWS = 80;
const MAX_REVIEW_ACTIONS = 120;
const MAX_REVIEW_OBSERVATIONS = 160;
const MAX_REVIEW_TEXT_CHARS = 1800;
const MAX_REVIEW_MESSAGE_CHARS = 1200;
const RULESET_VERSION = "2026-04-30";
const KEY_DB_NAME = "ardur-personal-keys";
const KEY_STORE = "crypto_keys";
const SIGNER_KEY_ID = "browser-local-p256-v1";
const NATIVE_HOST_NAME = "dev.ardur.personal";
const HOST_OBSERVATION_TYPE = "ardur.personal.host_observation.v0.1";

chrome.runtime.onInstalled.addListener(() => {
  initializeStorage().catch(() => {});
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((result) => sendResponse(result))
    .catch((error) => sendResponse({ ok: false, error: String(error) }));
  return true;
});

async function handleMessage(message, sender) {
  switch (message?.type) {
    case EVENT_TYPE:
      return handleObservedEvent(message, sender);
    case "ardur.personal.get_state":
      return popupState(message);
    case "ardur.personal.enable_origin":
      return enableOrigin(message.origin);
    case "ardur.personal.disable_origin":
      return disableOrigin(message.origin);
    case "ardur.personal.get_capture_policy":
      return capturePolicy(message.origin);
    case "ardur.personal.set_capture_snapshots":
      return setCaptureSnapshots(message.origin, message.enabled);
    case "ardur.personal.export_receipts":
      return exportReceipts();
    case "ardur.personal.forward_to_native":
      return forwardLatestToNative();
    default:
      return { ok: false, error: "unsupported message type" };
  }
}

async function initializeStorage() {
  const settings = await loadSettings();
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
  await getOrCreateSigningMaterial();
}

async function popupState(message) {
  const settings = await loadSettings();
  const receipts = await loadReceipts();
  const sessionReviews = await loadSessionReviews();
  const origin = normalizeOrigin(message?.origin || "");
  const originReviews = origin
    ? sessionReviews.filter((review) => review.origin === origin).slice(-10).reverse()
    : [];
  return {
    ok: true,
    origin,
    enabled: origin ? settings.enabledOrigins.includes(origin) : false,
    captureSnapshots: origin ? settings.captureSnapshotsOrigins.includes(origin) : false,
    settings,
    receipts: receipts.slice(-50).reverse(),
    sessionReviews: originReviews,
    latestReview: originReviews[0] || null
  };
}

async function enableOrigin(origin) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) {
    return { ok: false, error: "invalid origin" };
  }
  const settings = await loadSettings();
  if (!settings.enabledOrigins.includes(normalized)) {
    settings.enabledOrigins.push(normalized);
  }
  await saveSettings(settings);
  return { ok: true, settings };
}

async function disableOrigin(origin) {
  const normalized = normalizeOrigin(origin);
  const settings = await loadSettings();
  settings.enabledOrigins = settings.enabledOrigins.filter((item) => item !== normalized);
  settings.captureSnapshotsOrigins = settings.captureSnapshotsOrigins.filter(
    (item) => item !== normalized
  );
  await saveSettings(settings);
  return { ok: true, settings };
}

async function capturePolicy(origin) {
  const normalized = normalizeOrigin(origin);
  const settings = await loadSettings();
  return {
    ok: true,
    origin: normalized,
    captureSnapshots: normalized
      ? settings.captureSnapshotsOrigins.includes(normalized)
      : false
  };
}

async function setCaptureSnapshots(origin, enabledValue) {
  const normalized = normalizeOrigin(origin);
  if (!normalized) {
    return { ok: false, error: "invalid origin" };
  }
  const settings = await loadSettings();
  const enabled = enabledValue === true;
  if (enabled && !settings.enabledOrigins.includes(normalized)) {
    return { ok: false, error: "enable the site before capturing text snapshots" };
  }
  if (enabled && !settings.captureSnapshotsOrigins.includes(normalized)) {
    settings.captureSnapshotsOrigins.push(normalized);
  }
  if (!enabled) {
    settings.captureSnapshotsOrigins = settings.captureSnapshotsOrigins.filter(
      (item) => item !== normalized
    );
  }
  await saveSettings(settings);
  return { ok: true, settings };
}

async function handleObservedEvent(message, sender) {
  const validation = await validateObservedEvent(message, sender);
  if (!validation.ok) {
    return validation;
  }
  const policy = evaluatePolicy(message);
  const receipt = await buildReceipt(message, sender, policy);
  const receipts = await loadReceipts();
  receipts.push(receipt);
  while (receipts.length > MAX_RECEIPTS) {
    receipts.shift();
  }
  await chrome.storage.local.set({ [RECEIPTS_KEY]: receipts });
  await updateSessionReview(message, receipt, policy);
  if (policy.verdict === "blocked") {
    await applyBlockRule(message.origin);
  }
  return { ok: true, receipt_id: receipt.receipt_id, verdict: policy.verdict };
}

async function validateObservedEvent(message, sender) {
  if (message.source !== "content_script") {
    return { ok: false, error: "invalid source" };
  }
  const origin = normalizeOrigin(message.origin);
  if (!origin) {
    return { ok: false, error: "invalid origin" };
  }
  const senderOrigin = normalizeOrigin(sender?.url || sender?.tab?.url || "");
  if (senderOrigin && senderOrigin !== origin) {
    return { ok: false, error: "origin mismatch" };
  }
  const settings = await loadSettings();
  if (!settings.enabledOrigins.includes(origin)) {
    return { ok: false, error: "origin is not enabled" };
  }
  if (!Number.isInteger(message.frame_id) || message.frame_id < 0) {
    return { ok: false, error: "invalid frame id" };
  }
  if (typeof message.tab_session_id !== "string" || !message.tab_session_id) {
    return { ok: false, error: "invalid tab session id" };
  }
  if (!isIsoDate(message.observed_at)) {
    return { ok: false, error: "invalid observed_at" };
  }
  const event = message.event;
  if (!event || event.kind !== "dom_observed") {
    return { ok: false, error: "invalid event kind" };
  }
  if (!["observe", "read", "send", "write", "block", "allow"].includes(event.action_class)) {
    return { ok: false, error: "invalid action class" };
  }
  if (!/^sha-256:[0-9a-f]{64}$/.test(event.content_digest || "")) {
    return { ok: false, error: "invalid content digest" };
  }
  if (event.raw_content_included !== false) {
    return { ok: false, error: "raw content is disabled in this prototype" };
  }
  const review = message.review;
  if (review) {
    if (review.schema_version !== "ardur.personal.visible_session_snapshot.v0.1") {
      return { ok: false, error: "invalid review snapshot schema" };
    }
    if (review.origin !== origin) {
      return { ok: false, error: "review snapshot origin mismatch" };
    }
    if (review.text_snapshot_included === true) {
      const settings = await loadSettings();
      if (!settings.captureSnapshotsOrigins.includes(origin)) {
        return { ok: false, error: "text snapshot was sent without user consent" };
      }
    }
    if (JSON.stringify(review).length > 60000) {
      return { ok: false, error: "review snapshot is too large" };
    }
  }
  return { ok: true };
}

function evaluatePolicy(message) {
  const action = message.event.action_class;
  const target = String(message.event.target || "").toLowerCase();
  const sensitive = /\b(password|secret|token|api[-_ ]?key|ssn)\b/.test(target);
  if (["send", "write"].includes(action) && sensitive) {
    return {
      preset_id: "no-sensitive-upload",
      rule_id: "sensitive-target-block",
      verdict: "blocked"
    };
  }
  if (["observe", "read"].includes(action)) {
    return {
      preset_id: "digest-only-observation",
      rule_id: "digest-observe-allow",
      verdict: "allowed"
    };
  }
  return {
    preset_id: "manual-review",
    rule_id: "unknown-action",
    verdict: "unknown"
  };
}

async function buildReceipt(message, sender, policy) {
  const receipts = await loadReceipts();
  const previous = receipts.at(-1) || null;
  const previousHash = previous ? await sha256Hex(stableStringify(previous)) : null;
  const unsigned = {
    schema_version: RECEIPT_TYPE,
    receipt_id: crypto.randomUUID(),
    previous_receipt_hash: previousHash,
    observed_at: message.observed_at,
    extension: {
      extension_id: chrome.runtime.id,
      version: chrome.runtime.getManifest().version,
      ruleset_version: RULESET_VERSION
    },
    page: {
      origin: message.origin,
      tab_id: sender?.tab?.id ?? null,
      tab_session_id: message.tab_session_id,
      frame_id: message.frame_id
    },
    event: {
      kind: message.event.kind,
      action_class: message.event.action_class,
      target: message.event.target,
      content_digest: message.event.content_digest,
      raw_content_included: false
    },
    policy,
    user_decision: {
      decision: "none",
      decided_at: null
    },
    integrity: {
      canonicalization: "JCS",
      hash_alg: "sha-256",
      sign_alg: "ECDSA-P256-SHA256",
      signer_key_id: SIGNER_KEY_ID,
      signature: ""
    }
  };
  const signature = await signReceipt(unsigned);
  unsigned.integrity.signature = signature;
  return unsigned;
}

async function signReceipt(receipt) {
  const { privateKey } = await getOrCreateSigningMaterial();
  const material = structuredClone(receipt);
  material.integrity.signature = "";
  const encoded = new TextEncoder().encode(stableStringify(material));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    encoded
  );
  return base64Url(new Uint8Array(signature));
}

async function getOrCreateSigningMaterial() {
  const db = await openKeyDb();
  const existing = await idbGet(db, SIGNER_KEY_ID);
  if (existing?.privateKey && existing?.publicJwk) {
    return existing;
  }
  const generated = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const privateJwk = await crypto.subtle.exportKey("jwk", generated.privateKey);
  const publicJwk = await crypto.subtle.exportKey("jwk", generated.publicKey);
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    privateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const value = { privateKey, publicJwk, createdAt: new Date().toISOString() };
  await idbPut(db, SIGNER_KEY_ID, value);
  return value;
}

async function applyBlockRule(origin) {
  if (!chrome.declarativeNetRequest?.updateDynamicRules) {
    return;
  }
  const id = dynamicRuleId(origin);
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [id],
    addRules: [
      {
        id,
        priority: 1,
        action: { type: "block" },
        condition: {
          urlFilter: `${origin}*`,
          resourceTypes: ["main_frame", "xmlhttprequest"]
        }
      }
    ]
  });
}

async function forwardLatestToNative() {
  const hasPermission = await chrome.permissions.contains({
    permissions: ["nativeMessaging"]
  });
  if (!hasPermission) {
    return { ok: false, error: "nativeMessaging permission is not enabled" };
  }
  const receipts = await loadReceipts();
  const latest = receipts.at(-1);
  if (!latest) {
    return { ok: false, error: "no receipt to forward" };
  }
  const { publicJwk } = await getOrCreateSigningMaterial();
  const sessionReview = await latestSessionReviewForReceipt(latest.receipt_id);
  const response = await chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, {
    type: HOST_OBSERVATION_TYPE,
    forwarded_at: new Date().toISOString(),
    extension: {
      extension_id: chrome.runtime.id,
      version: chrome.runtime.getManifest().version
    },
    browser_receipt: latest,
    session_review: sessionReview,
    browser_signer: {
      key_id: SIGNER_KEY_ID,
      public_jwk: publicJwk
    }
  });
  if (!response?.ok) {
    return {
      ok: false,
      error: response?.error || "native host rejected receipt",
      error_code: response?.error_code || "native_host_rejected",
      response
    };
  }
  return { ok: true, response };
}

async function exportReceipts() {
  const { publicJwk } = await getOrCreateSigningMaterial();
  return {
    ok: true,
    exported_at: new Date().toISOString(),
    schema_version: "ardur.personal.browser_receipt_export.v0.1",
    signer: {
      key_id: SIGNER_KEY_ID,
      public_jwk: publicJwk
    },
    receipts: await loadReceipts(),
    session_reviews: await loadSessionReviews()
  };
}

async function loadSettings() {
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  return {
    enabledOrigins: [],
    captureSnapshotsOrigins: [],
    nativeHostEnabled: false,
    ...stored[SETTINGS_KEY]
  };
}

async function saveSettings(settings) {
  await chrome.storage.local.set({ [SETTINGS_KEY]: settings });
}

async function loadReceipts() {
  const stored = await chrome.storage.local.get(RECEIPTS_KEY);
  return Array.isArray(stored[RECEIPTS_KEY]) ? stored[RECEIPTS_KEY] : [];
}

async function loadSessionReviews() {
  const stored = await chrome.storage.local.get(SESSION_REVIEWS_KEY);
  return Array.isArray(stored[SESSION_REVIEWS_KEY]) ? stored[SESSION_REVIEWS_KEY] : [];
}

async function saveSessionReviews(sessionReviews) {
  await chrome.storage.local.set({
    [SESSION_REVIEWS_KEY]: sessionReviews.slice(-MAX_SESSION_REVIEWS)
  });
}

async function updateSessionReview(message, receipt, policy) {
  const snapshot = sanitizeReviewSnapshot(message.review, message.origin);
  const reviews = await loadSessionReviews();
  const sessionId = `${message.origin}:${message.tab_session_id}`;
  let review = reviews.find((item) => item.session_id === sessionId);
  if (!review) {
    review = {
      schema_version: "ardur.personal.session_review.v0.1",
      session_id: sessionId,
      origin: message.origin,
      provider: snapshot.provider,
      title: snapshot.title,
      started_at: message.observed_at,
      updated_at: message.observed_at,
      capture_mode: snapshot.capture_mode,
      text_snapshot_included: snapshot.text_snapshot_included,
      policy_labels: [],
      status: "active",
      summary: "",
      latest_receipt_id: "",
      latest_receipt_hash: "",
      latest_action: null,
      observations: [],
      actions: [],
      integrity: reviewIntegrityShell()
    };
    reviews.push(review);
  }

  const receiptHash = await sha256Hex(stableStringify(receipt));
  const observation = {
    receipt_id: receipt.receipt_id,
    observed_at: receipt.observed_at,
    target: receipt.event.target,
    action_class: receipt.event.action_class,
    content_digest: receipt.event.content_digest,
    verdict: policy.verdict,
    labels: policyLabels(policy.verdict),
    capture_mode: snapshot.capture_mode
  };
  review.observations.push(observation);
  review.observations = review.observations.slice(-MAX_REVIEW_OBSERVATIONS);

  const actions = deriveActions(review, snapshot, receipt, policy);
  if (actions.length > 0) {
    review.actions.push(...actions);
    review.actions = dedupeActions(review.actions).slice(-MAX_REVIEW_ACTIONS);
    review.latest_action = review.actions.at(-1);
  }

  review.provider = snapshot.provider || review.provider;
  review.title = snapshot.title || review.title;
  review.updated_at = receipt.observed_at;
  review.capture_mode = snapshot.capture_mode;
  review.text_snapshot_included = snapshot.text_snapshot_included;
  review.policy_labels = mergedLabels(review.policy_labels, observation.labels);
  review.latest_receipt_id = receipt.receipt_id;
  review.latest_receipt_hash = receiptHash;
  review.summary = generateSessionSummary(review);
  review.integrity = reviewIntegrityShell();
  review.integrity.signature = await signReview(review);
  await saveSessionReviews(reviews);
}

function sanitizeReviewSnapshot(snapshot, origin) {
  if (!snapshot || snapshot.schema_version !== "ardur.personal.visible_session_snapshot.v0.1") {
    return {
      provider: "Generic AI Website",
      title: "",
      boundary_reason: "observed_event",
      capture_mode: "digest_only",
      text_snapshot_included: false,
      visible_text_digest: "",
      visible_text_excerpt: "",
      messages: []
    };
  }
  const includeText = snapshot.text_snapshot_included === true;
  return {
    provider: cleanText(snapshot.provider || "Generic AI Website", 80),
    title: cleanText(snapshot.title || "", 160),
    origin,
    boundary_reason: cleanText(snapshot.boundary_reason || "observed_event", 80),
    capture_mode: includeText ? "structured_visible_text" : "digest_only",
    text_snapshot_included: includeText,
    visible_text_digest: /^sha-256:[0-9a-f]{64}$/.test(snapshot.visible_text_digest || "")
      ? snapshot.visible_text_digest
      : "",
    visible_text_excerpt: includeText
      ? cleanText(snapshot.visible_text_excerpt || "", MAX_REVIEW_TEXT_CHARS)
      : "",
    messages: includeText ? sanitizeMessages(snapshot.messages) : []
  };
}

function sanitizeMessages(messages) {
  if (!Array.isArray(messages)) {
    return [];
  }
  return messages.slice(-12).map((message) => ({
    role: ["user", "assistant", "tool", "system", "unknown"].includes(message.role)
      ? message.role
      : "unknown",
    text_digest: /^sha-256:[0-9a-f]{64}$/.test(message.text_digest || "")
      ? message.text_digest
      : "",
    text_excerpt: cleanText(message.text_excerpt || "", MAX_REVIEW_MESSAGE_CHARS),
    source: cleanText(message.source || "visible_text", 40)
  })).filter((message) => message.text_digest || message.text_excerpt);
}

function deriveActions(review, snapshot, receipt, policy) {
  const existingDigests = new Set(
    review.actions
      .map((action) => action.message_digest || action.visible_text_digest)
      .filter(Boolean)
  );
  const actions = [];
  for (const message of snapshot.messages) {
    if (!message.text_digest || existingDigests.has(message.text_digest)) {
      continue;
    }
    const kind = actionKindForRole(message.role);
    actions.push({
      action_id: crypto.randomUUID(),
      observed_at: receipt.observed_at,
      kind,
      role: message.role,
      provider: snapshot.provider,
      summary: actionSummary(kind, message),
      text_excerpt: message.text_excerpt,
      message_digest: message.text_digest,
      receipt_id: receipt.receipt_id,
      policy_labels: policyLabels(policy.verdict)
    });
    existingDigests.add(message.text_digest);
  }
  if (actions.length === 0 && snapshot.visible_text_digest) {
    const lastObservation = review.observations.at(-2);
    if (!lastObservation || lastObservation.content_digest !== snapshot.visible_text_digest) {
      actions.push({
        action_id: crypto.randomUUID(),
        observed_at: receipt.observed_at,
        kind: "visible_page_state_changed",
        role: "unknown",
        provider: snapshot.provider,
        summary: "Visible page state changed.",
        text_excerpt: snapshot.visible_text_excerpt,
        visible_text_digest: snapshot.visible_text_digest,
        receipt_id: receipt.receipt_id,
        policy_labels: policyLabels(policy.verdict)
      });
    }
  }
  return actions;
}

function actionKindForRole(role) {
  if (role === "user") {
    return "user_prompt_observed";
  }
  if (role === "assistant") {
    return "assistant_response_observed";
  }
  if (role === "tool") {
    return "tool_output_observed";
  }
  return "visible_message_observed";
}

function actionSummary(kind, message) {
  const excerpt = message.text_excerpt ? `: ${message.text_excerpt}` : ".";
  if (kind === "user_prompt_observed") {
    return `User prompt observed${excerpt}`;
  }
  if (kind === "assistant_response_observed") {
    return `Assistant response observed${excerpt}`;
  }
  if (kind === "tool_output_observed") {
    return `Tool output observed${excerpt}`;
  }
  return `Visible message observed${excerpt}`;
}

function policyLabels(verdict) {
  const labels = ["observed", "attested"];
  if (verdict === "allowed") {
    labels.push("allowed");
  } else if (verdict === "blocked") {
    labels.push("blocked");
  } else {
    labels.push("unknown");
  }
  return labels;
}

function mergedLabels(existing, next) {
  return [...new Set([...(existing || []), ...(next || [])])];
}

function dedupeActions(actions) {
  const seen = new Set();
  const result = [];
  for (const action of actions) {
    const key = action.message_digest || action.visible_text_digest || action.action_id;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    result.push(action);
  }
  return result;
}

function generateSessionSummary(review) {
  const actionCount = review.actions.length;
  const observationCount = review.observations.length;
  const provider = review.provider || "AI website";
  const labels = review.policy_labels.length ? review.policy_labels.join(", ") : "observed";
  const latest = review.latest_action?.summary || "No readable action text captured yet.";
  return `${provider} session review: ${actionCount} action boundary/boundaries, ${observationCount} receipt(s), labels: ${labels}. Latest: ${latest}`;
}

function cleanText(value, maxChars) {
  return String(value)
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxChars);
}

function reviewIntegrityShell() {
  return {
    canonicalization: "JCS",
    hash_alg: "sha-256",
    sign_alg: "ECDSA-P256-SHA256",
    signer_key_id: SIGNER_KEY_ID,
    signature: ""
  };
}

async function signReview(review) {
  const { privateKey } = await getOrCreateSigningMaterial();
  const material = structuredClone(review);
  material.integrity.signature = "";
  const encoded = new TextEncoder().encode(stableStringify(material));
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    encoded
  );
  return base64Url(new Uint8Array(signature));
}

async function latestSessionReviewForReceipt(receiptId) {
  const reviews = await loadSessionReviews();
  return reviews.find((review) => review.latest_receipt_id === receiptId)
    || reviews.find((review) => review.observations.some((item) => item.receipt_id === receiptId))
    || null;
}

function normalizeOrigin(value) {
  try {
    return new URL(value).origin;
  } catch {
    return "";
  }
}

function isIsoDate(value) {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function dynamicRuleId(origin) {
  let hash = 0;
  for (const char of origin) {
    hash = (hash * 31 + char.charCodeAt(0)) % 100000;
  }
  return 1000 + hash;
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => stableStringify(item)).join(",")}]`;
  }
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}

async function sha256Hex(text) {
  const encoded = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", encoded);
  return [...new Uint8Array(digest)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

function base64Url(bytes) {
  let binary = "";
  for (const value of bytes) {
    binary += String.fromCharCode(value);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function openKeyDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(KEY_DB_NAME, 1);
    request.onupgradeneeded = () => {
      request.result.createObjectStore(KEY_STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idbGet(db, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, "readonly");
    const request = tx.objectStore(KEY_STORE).get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idbPut(db, key, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, "readwrite");
    tx.objectStore(KEY_STORE).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

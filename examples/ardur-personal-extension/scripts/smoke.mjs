import { createServer } from "node:http";
import { existsSync, readdirSync, rmSync } from "node:fs";
import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { createServer as createNetServer } from "node:net";
import { createHash, createVerify } from "node:crypto";
import { homedir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, "..", "..", "..");
const sourceExtensionPath = resolve(repoRoot, "examples", "ardur-personal-extension");
const workDir = resolve(repoRoot, ".context", "extension-smoke");
const profileDir = resolve(workDir, "chrome-profile");
const preparedExtensionPath = resolve(workDir, "loaded-extension");
const fakeHomeDir = resolve(workDir, "home");
const nativeHostStoreDir = resolve(workDir, "native-host-store");
const nativeHostName = "dev.ardur.personal";
const nativeHostWrapperPath = resolve(
  repoRoot,
  "examples",
  "ardur-personal-native-host",
  "ardur-personal-host"
);
const nativeSmokeEnabled = process.env.WITH_NATIVE_HOST === "1";
const testPage = `<!doctype html>
<html>
  <head><title>Ardur Personal Smoke</title></head>
  <body>
    <main>
      <h1>Smoke Test AI Tool</h1>
      <section id="tool-panel" data-testid="conversation">
        <article data-message-author-role="user">
          Summarize this customer record without sending raw content.
        </article>
        <article id="assistant-message" data-message-author-role="assistant">
          Working on the answer.
        </article>
      </section>
    </main>
  </body>
</html>`;

function playwrightChromeCandidates() {
  const cacheRoot = process.env.PLAYWRIGHT_BROWSERS_PATH
    || resolve(homedir(), "Library", "Caches", "ms-playwright");
  if (!existsSync(cacheRoot)) {
    return [];
  }
  return readdirSync(cacheRoot)
    .filter((entry) => entry.startsWith("chromium-"))
    .sort()
    .reverse()
    .flatMap((entry) => {
      const root = resolve(cacheRoot, entry);
      return [
        resolve(root, "chrome-mac-arm64", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"),
        resolve(root, "chrome-mac", "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing"),
        resolve(root, "chrome-linux", "chrome"),
        resolve(root, "chrome-win", "chrome.exe")
      ];
    });
}

const chromeCandidates = [
  process.env.CHROME_PATH,
  ...playwrightChromeCandidates(),
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "chromium",
  "chromium-browser"
].filter(Boolean);

if (process.env.ALLOW_BRANDED_CHROME === "1") {
  chromeCandidates.push(
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "google-chrome"
  );
}

function chromePath() {
  for (const candidate of chromeCandidates) {
    if (candidate.includes("/") && existsSync(candidate)) {
      return candidate;
    }
    if (!candidate.includes("/")) {
      const result = spawnSync(candidate, ["--version"], { stdio: "ignore" });
      if (!result.error) {
        return candidate;
      }
    }
  }
  throw new Error(
    "Chrome for Testing or Chromium executable not found; set CHROME_PATH to a compatible browser"
  );
}

function nativeHostManifestPaths(homeDir) {
  return [
    resolve(profileDir, "NativeMessagingHosts", `${nativeHostName}.json`),
    resolve(homeDir, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts", `${nativeHostName}.json`),
    resolve(homeDir, "Library", "Application Support", "Google", "Chrome for Testing", "NativeMessagingHosts", `${nativeHostName}.json`),
    resolve(homeDir, "Library", "Application Support", "Google", "ChromeForTesting", "NativeMessagingHosts", `${nativeHostName}.json`),
    resolve(homeDir, "Library", "Application Support", "Chromium", "NativeMessagingHosts", `${nativeHostName}.json`),
    resolve(homeDir, ".config", "google-chrome", "NativeMessagingHosts", `${nativeHostName}.json`),
    resolve(homeDir, ".config", "chromium", "NativeMessagingHosts", `${nativeHostName}.json`)
  ];
}

async function installNativeHostManifests(extensionId) {
  const manifest = {
    name: nativeHostName,
    description: "Ardur Personal native messaging host",
    path: nativeHostWrapperPath,
    type: "stdio",
    allowed_origins: [`chrome-extension://${extensionId}/`]
  };
  const paths = nativeHostManifestPaths(fakeHomeDir);
  for (const path of paths) {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(manifest, null, 2)}\n`);
  }
  return paths;
}

function base64UrlToBuffer(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  return Buffer.from(padded, "base64");
}

function verifyEs256Jwt(token, publicKeyPem) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("host receipt JWT is malformed");
  }
  const verifier = createVerify("SHA256");
  verifier.update(`${parts[0]}.${parts[1]}`, "ascii");
  verifier.end();
  const signature = base64UrlToBuffer(parts[2]);
  const verified = verifier.verify(
    { key: publicKeyPem, dsaEncoding: "ieee-p1363" },
    signature
  );
  const claims = JSON.parse(base64UrlToBuffer(parts[1]).toString("utf-8"));
  return { verified, claims };
}

async function waitForNativeRecord(recordsPath, timeoutMs = 10000) {
  const started = Date.now();
  let lastError = null;
  while (Date.now() - started < timeoutMs) {
    try {
      const contents = await readFile(recordsPath, "utf-8");
      const lines = contents.trim().split("\n").filter(Boolean);
      if (lines.length > 0) {
        return JSON.parse(lines.at(-1));
      }
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 200));
  }
  throw lastError || new Error(`timed out waiting for ${recordsPath}`);
}

function stopProcess(child, timeoutMs = 5000) {
  return new Promise((resolveStop) => {
    if (child.exitCode !== null || child.signalCode !== null) {
      resolveStop();
      return;
    }
    let settled = false;
    const finish = () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolveStop();
      }
    };
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish();
    }, timeoutMs);
    child.once("exit", finish);
    child.kill("SIGTERM");
  });
}

function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = createNetServer();
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      server.close(() => resolvePort(address.port));
    });
    server.on("error", reject);
  });
}

function servePage() {
  const server = createServer((_, response) => {
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end(testPage);
  });
  return new Promise((resolveServer, reject) => {
    server.listen(0, "127.0.0.1", () => resolveServer(server));
    server.on("error", reject);
  });
}

async function fetchJson(url) {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`${url} returned ${response.status}`);
  }
  return response.json();
}

async function waitForJson(url, timeoutMs = 15000) {
  const started = Date.now();
  let lastError = null;
  while (Date.now() - started < timeoutMs) {
    try {
      return await fetchJson(url);
    } catch (error) {
      lastError = error;
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 200));
    }
  }
  throw lastError || new Error(`timed out waiting for ${url}`);
}

async function waitForTarget(debugPort, predicate, timeoutMs = 20000) {
  const started = Date.now();
  let lastTargets = [];
  while (Date.now() - started < timeoutMs) {
    const targets = await fetchJson(`http://127.0.0.1:${debugPort}/json/list`);
    lastTargets = targets.map((target) => ({
      type: target.type,
      title: target.title,
      url: target.url
    }));
    const target = targets.find(predicate);
    if (target) {
      return target;
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
  }
  throw new Error(`timed out waiting for Chrome target: ${JSON.stringify(lastTargets)}`);
}

class Cdp {
  constructor(url) {
    this.nextId = 1;
    this.pending = new Map();
    this.socket = new WebSocket(url);
    this.ready = new Promise((resolveReady, rejectReady) => {
      this.socket.addEventListener("open", resolveReady, { once: true });
      this.socket.addEventListener("error", rejectReady, { once: true });
    });
    this.socket.addEventListener("message", (event) => {
      const message = JSON.parse(event.data);
      if (!message.id || !this.pending.has(message.id)) {
        return;
      }
      const { resolveMessage, rejectMessage } = this.pending.get(message.id);
      this.pending.delete(message.id);
      if (message.error) {
        rejectMessage(new Error(message.error.message));
      } else {
        resolveMessage(message.result);
      }
    });
  }

  async send(method, params = {}) {
    await this.ready;
    const id = this.nextId++;
    const payload = JSON.stringify({ id, method, params });
    const promise = new Promise((resolveMessage, rejectMessage) => {
      this.pending.set(id, { resolveMessage, rejectMessage });
    });
    this.socket.send(payload);
    return promise;
  }

  close() {
    this.socket.close();
  }
}

async function main() {
  await mkdir(workDir, { recursive: true });
  await writeFile(resolve(workDir, "test-page.html"), testPage);
  rmSync(profileDir, { recursive: true, force: true });
  if (nativeSmokeEnabled) {
    rmSync(fakeHomeDir, { recursive: true, force: true });
    rmSync(nativeHostStoreDir, { recursive: true, force: true });
    await mkdir(resolve(fakeHomeDir, ".config"), { recursive: true });
  }

  const pageServer = await servePage();
  const pagePort = pageServer.address().port;
  const debugPort = await freePort();
  const origin = `http://127.0.0.1:${pagePort}`;
  const pageUrl = `${origin}/test-page.html`;
  rmSync(preparedExtensionPath, { recursive: true, force: true });
  await cp(sourceExtensionPath, preparedExtensionPath, { recursive: true });
  const manifestPath = resolve(preparedExtensionPath, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf-8"));
  manifest.host_permissions = ["http://127.0.0.1/*"];
  if (nativeSmokeEnabled && !manifest.permissions.includes("nativeMessaging")) {
    manifest.permissions.push("nativeMessaging");
    manifest.optional_permissions = (manifest.optional_permissions || [])
      .filter((permission) => permission !== "nativeMessaging");
  }
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

  const chromeArgs = [
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    `--user-data-dir=${profileDir}`,
    `--remote-debugging-port=${debugPort}`,
    `--disable-extensions-except=${preparedExtensionPath}`,
    `--load-extension=${preparedExtensionPath}`,
    pageUrl
  ];
  if (process.env.HEADLESS !== "0") {
    chromeArgs.unshift("--headless=new");
  }
  const chrome = spawn(chromePath(), chromeArgs, {
    stdio: ["ignore", "pipe", "pipe"],
    env: {
      ...process.env,
      ...(nativeSmokeEnabled
        ? {
            ARDUR_PERSONAL_HOST_DIR: nativeHostStoreDir,
            HOME: fakeHomeDir,
            XDG_CONFIG_HOME: resolve(fakeHomeDir, ".config")
          }
        : {})
    }
  });
  let chromeStdout = "";
  let chromeStderr = "";
  chrome.stdout.on("data", (chunk) => {
    chromeStdout += chunk.toString();
  });
  chrome.stderr.on("data", (chunk) => {
    chromeStderr += chunk.toString();
  });

  try {
    await waitForJson(`http://127.0.0.1:${debugPort}/json/version`);
    const serviceWorker = await waitForTarget(
      debugPort,
      (target) => target.type === "service_worker"
        && target.url.endsWith("/src/service_worker.js")
    );
    const extensionId = serviceWorker.url.match(/^chrome-extension:\/\/([^/]+)\//)?.[1];
    if (!extensionId) {
      throw new Error(`cannot derive extension id from ${serviceWorker.url}`);
    }
    const nativeManifestPaths = nativeSmokeEnabled
      ? await installNativeHostManifests(extensionId)
      : [];
    await waitForTarget(
      debugPort,
      (target) => target.type === "page" && target.url === pageUrl
    );
    const cdp = new Cdp(serviceWorker.webSocketDebuggerUrl);
    const expression = `(${async function smoke(originValue, nativeEnabled) {
      const timeout = (promise, label, ms = 10000) => Promise.race([
        promise,
        new Promise((_, reject) => {
          setTimeout(() => reject(new Error(`${label} timed out`)), ms);
        })
      ]);
      const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
      const settingsKey = "ardur_personal_settings";
      const receiptsKey = "ardur_personal_receipts";
      const sessionReviewsKey = "ardur_personal_session_reviews";
      const keyDbName = "ardur-personal-keys";
      const keyStore = "crypto_keys";
      const signerKeyId = "browser-local-p256-v1";
      if (!globalThis.chrome?.storage?.local) {
        return {
          ok: false,
          error: "chrome.storage.local unavailable",
          href: globalThis.location?.href || "",
          chromeKeys: globalThis.chrome ? Object.keys(globalThis.chrome) : [],
          manifest: globalThis.chrome?.runtime?.getManifest
            ? globalThis.chrome.runtime.getManifest()
            : null
        };
      }
      await timeout(chrome.storage.local.set({
        [settingsKey]: {
          enabledOrigins: [originValue],
          captureSnapshotsOrigins: [originValue],
          nativeHostEnabled: nativeEnabled
        }
      }), "storage set");
      const tabs = await timeout(chrome.tabs.query({}), "tabs query");
      const tab = tabs.find((item) => item.url && item.url.startsWith(originValue));
      if (!tab) {
        return { ok: false, error: "test tab not found", tabs };
      }
      await timeout(chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ["src/content_script.js"]
      }), "script injection");
      await delay(800);
      await timeout(chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          document.getElementById("assistant-message").textContent =
            "Final answer: the visible customer record was summarized locally for review.";
        }
      }), "page mutation");
      await timeout(chrome.tabs.sendMessage(tab.id, {
        type: "ardur.personal.collect_now"
      }), "manual collect");
      await delay(2500);
      const stored = await timeout(
        chrome.storage.local.get([receiptsKey, sessionReviewsKey]),
        "storage get"
      );
      const receipts = stored[receiptsKey] || [];
      const sessionReviews = stored[sessionReviewsKey] || [];
      const latest = receipts.at(-1);
      const latestReview = sessionReviews.at(-1);
      if (!latest) {
        return { ok: false, error: "no receipt created", stored };
      }
      if (!latestReview) {
        return { ok: false, error: "no session review created", stored };
      }
      if (!latestReview.text_snapshot_included || latestReview.actions.length < 2) {
        return { ok: false, error: "session review did not capture readable actions", latestReview };
      }
      const openDb = () => new Promise((resolve, reject) => {
        const request = indexedDB.open(keyDbName, 1);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      const idbGet = (db, key) => new Promise((resolve, reject) => {
        const tx = db.transaction(keyStore, "readonly");
        const request = tx.objectStore(keyStore).get(key);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      });
      const stableStringify = (value) => {
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
      };
      const db = await openDb();
      const keyMaterial = await idbGet(db, signerKeyId);
      const material = structuredClone(latest);
      const signature = material.integrity.signature;
      material.integrity.signature = "";
      const publicKey = await crypto.subtle.importKey(
        "jwk",
        keyMaterial.publicJwk,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"]
      );
      const normalized = signature.replace(/-/g, "+").replace(/_/g, "/");
      const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
      const signatureBytes = Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
      const verified = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        publicKey,
        signatureBytes,
        new TextEncoder().encode(stableStringify(material))
      );
      let nativeForward = null;
      if (nativeEnabled) {
        const response = await timeout(
          chrome.runtime.sendNativeMessage("dev.ardur.personal", {
            type: "ardur.personal.host_observation.v0.1",
            forwarded_at: new Date().toISOString(),
            extension: {
              extension_id: chrome.runtime.id,
              version: chrome.runtime.getManifest().version
            },
            browser_receipt: latest,
            session_review: latestReview,
            browser_signer: {
              key_id: signerKeyId,
              public_jwk: keyMaterial.publicJwk
            }
          }),
          "native forward",
          15000
        );
        nativeForward = { ok: true, response };
        if (!nativeForward.response?.ok) {
          return { ok: false, error: "native forward failed", nativeForward };
        }
      }
      return {
        ok: true,
        enabledOrigin: originValue,
        nativeEnabled,
        receiptCount: receipts.length,
        sessionReview: {
          provider: latestReview.provider,
          actionCount: latestReview.actions.length,
          labels: latestReview.policy_labels,
          summary: latestReview.summary,
          textSnapshotIncluded: latestReview.text_snapshot_included,
          latestReceiptId: latestReview.latest_receipt_id
        },
        latestReceipt: {
          schema_version: latest.schema_version,
          origin: latest.page.origin,
          action_class: latest.event.action_class,
          raw_content_included: latest.event.raw_content_included,
          content_digest: latest.event.content_digest,
          previous_receipt_hash: latest.previous_receipt_hash,
          signature_length: signature.length
        },
        signatureVerified: verified,
        nativeForward
      };
    }.toString()})(${JSON.stringify(origin)}, ${JSON.stringify(nativeSmokeEnabled)})`;
    const result = await cdp.send("Runtime.evaluate", {
      expression,
      awaitPromise: true,
      returnByValue: true
    });
    cdp.close();
    if (result.exceptionDetails) {
      throw new Error(JSON.stringify(result.exceptionDetails));
    }
    const value = result.result.value;
    if (!value?.ok || !value.signatureVerified) {
      throw new Error(JSON.stringify(value, null, 2));
    }
    if (value.latestReceipt.raw_content_included !== false) {
      throw new Error("receipt unexpectedly includes raw content");
    }
    if (!/^sha-256:[0-9a-f]{64}$/.test(value.latestReceipt.content_digest)) {
      throw new Error("receipt content digest is malformed");
    }
    if (nativeSmokeEnabled) {
      const nativeResponse = value.nativeForward.response;
      const hostReceiptHash = createHash("sha256")
        .update(nativeResponse.host_receipt_jwt, "ascii")
        .digest("hex");
      if (hostReceiptHash !== nativeResponse.host_receipt_hash) {
        throw new Error("native host receipt hash mismatch");
      }
      const hostJwt = verifyEs256Jwt(
        nativeResponse.host_receipt_jwt,
        nativeResponse.host_public_key_pem
      );
      if (!hostJwt.verified) {
        throw new Error("native host receipt JWT signature did not verify");
      }
      const recordsFile = resolve(nativeHostStoreDir, "receipts.jsonl");
      const record = await waitForNativeRecord(recordsFile);
      if (record.browser_signature_verified !== true) {
        throw new Error("native record did not verify browser signature");
      }
      if (record.host_receipt_hash !== nativeResponse.host_receipt_hash) {
        throw new Error("native record hash does not match native response");
      }
      if (record.session_review_verified !== true) {
        throw new Error("native record did not verify session review");
      }
      value.nativeForward = {
        ok: true,
        response: {
          ok: true,
          browser_receipt_id: nativeResponse.browser_receipt_id,
          browser_signature_verified: nativeResponse.browser_signature_verified,
          host_receipt_id: nativeResponse.host_receipt_id,
          host_receipt_hash: nativeResponse.host_receipt_hash,
          session_review_verified: nativeResponse.session_review_verified,
          session_review_hash: nativeResponse.session_review_hash,
          records_file: nativeResponse.records_file
        }
      };
      value.nativeHost = {
        manifestPathCount: nativeManifestPaths.length,
        recordsFile,
        hostReceipt: {
          receipt_id: hostJwt.claims.receipt_id,
          verdict: hostJwt.claims.verdict,
          action_class: hostJwt.claims.action_class,
          target: hostJwt.claims.target,
          evidence_proof_ref: hostJwt.claims.evidence_proof_ref,
          signatureVerified: true
        }
      };
    }
    console.log(JSON.stringify(value, null, 2));
  } catch (error) {
    const chromeOutput = [
      chromeStderr ? `Chrome stderr:\n${chromeStderr.slice(-6000)}` : "",
      chromeStdout ? `Chrome stdout:\n${chromeStdout.slice(-2000)}` : ""
    ].filter(Boolean).join("\n");
    if (chromeOutput) {
      throw new Error(`${error.message}\n${chromeOutput}`);
    }
    throw error;
  } finally {
    await stopProcess(chrome);
    pageServer.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

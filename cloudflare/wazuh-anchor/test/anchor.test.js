import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { canonicalUnsigned, encodeBase64URL, handle } from "../src/index.js";

class FakeBucket {
  constructor() {
    this.objects = new Map();
    this.puts = 0;
  }

  async put(key, value, options) {
    this.puts += 1;
    if (options.onlyIf.get("if-none-match") === "*" && this.objects.has(key)) return null;
    const bytes = new Uint8Array(value);
    this.objects.set(key, bytes.slice());
    return { key };
  }

  async get(key) {
    const value = this.objects.get(key);
    if (!value) return null;
    return { arrayBuffer: async () => value.slice().buffer };
  }
}

async function fixture() {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const chainHash = new Uint8Array(32);
  chainHash.fill(0x42);
  const unsigned = {
    version: 1,
    kind: "wazuh-daily-hash-anchor",
    source: "plntir-siem-01",
    date: "2026-09-04",
    sequence: 17,
    chain_hash: encodeBase64URL(chainHash),
    created_at: "2026-09-04T12:00:00Z",
    deduplication_id: "anchor-2026-09-04-17",
  };
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, canonicalUnsigned(unsigned)),
  );
  const anchor = { ...unsigned, signature: encodeBase64URL(signature) };
  const order = [
    "chain_hash",
    "created_at",
    "date",
    "deduplication_id",
    "kind",
    "sequence",
    "signature",
    "source",
    "version",
  ];
  const ordered = {};
  for (const key of order) ordered[key] = anchor[key];
  const body = `${JSON.stringify(ordered)}\n`;
  const bucket = new FakeBucket();
  const environment = {
    EXPECTED_HOSTNAME: "anchor.plntir.invalid",
    WAZUH_ANCHOR_VERIFY_KEY: encodeBase64URL(publicKey),
    WAZUH_MTLS_CERT_SHA256: "a".repeat(64),
    WAZUH_ANCHORS: bucket,
  };
  return { anchor, body, bucket, environment };
}

function request(body, environment, fingerprint = "a".repeat(64)) {
  const value = new Request(`https://${environment.EXPECTED_HOSTNAME}/internal/v1/wazuh/hash-anchor`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Content-Length": String(Buffer.byteLength(body)) },
    body,
  });
  Object.defineProperty(value, "cf", {
    value: { tlsClientAuth: { certVerify: "SUCCESS", certFingerprintSHA256: fingerprint } },
  });
  return value;
}

test("stores one signed mTLS-bound daily anchor and makes retry idempotent", async () => {
  const value = await fixture();
  const first = await handle(
    request(value.body, value.environment),
    value.environment,
    Date.parse("2026-09-04T12:01:00Z"),
  );
  assert.equal(first.status, 201);
  const retry = await handle(
    request(value.body, value.environment),
    value.environment,
    Date.parse("2026-09-04T12:02:00Z"),
  );
  assert.equal(retry.status, 204);
  assert.equal(value.bucket.objects.size, 1);
});

test("conceals the endpoint without the exact verified client certificate", async () => {
  const value = await fixture();
  const result = await handle(
    request(value.body, value.environment, "b".repeat(64)),
    value.environment,
    Date.parse("2026-09-04T12:01:00Z"),
  );
  assert.equal(result.status, 404);
  assert.equal(value.bucket.puts, 0);
});

test("rejects a validly shaped but corrupted Ed25519 signature", async () => {
  const value = await fixture();
  const replacement = `${value.anchor.signature[0] === "A" ? "B" : "A"}${value.anchor.signature.slice(1)}`;
  const changed = value.body.replace(value.anchor.signature, replacement);
  const result = await handle(
    request(changed, value.environment),
    value.environment,
    Date.parse("2026-09-04T12:01:00Z"),
  );
  assert.equal(result.status, 401);
  assert.equal(value.bucket.puts, 0);
});

test("rejects noncanonical JSON before storage", async () => {
  const value = await fixture();
  const noncanonical = JSON.stringify(JSON.parse(value.body));
  const result = await handle(
    request(noncanonical, value.environment),
    value.environment,
    Date.parse("2026-09-04T12:01:00Z"),
  );
  assert.equal(result.status, 400);
});

test("rejects a semantically unrelated deduplication id before signature work", async () => {
  const value = await fixture();
  const changed = value.body.replace("anchor-2026-09-04-17", "anchor-unrelated-17");
  const result = await handle(
    request(changed, value.environment),
    value.environment,
    Date.parse("2026-09-04T12:01:00Z"),
  );
  assert.equal(result.status, 400);
  assert.equal(value.bucket.puts, 0);
});

test("refuses a second different anchor for the same UTC date", async () => {
  const value = await fixture();
  const first = await handle(
    request(value.body, value.environment),
    value.environment,
    Date.parse("2026-09-04T12:01:00Z"),
  );
  assert.equal(first.status, 201);
  value.bucket.objects.set("anchors/2026-09-04.json", new TextEncoder().encode("different\n"));
  const conflict = await handle(
    request(value.body, value.environment),
    value.environment,
    Date.parse("2026-09-04T12:02:00Z"),
  );
  assert.equal(conflict.status, 409);
});

test("sentinel configuration cannot serve requests", async () => {
  const value = await fixture();
  value.environment.WAZUH_ANCHOR_VERIFY_KEY = "SET_AT_PRODUCTION_SEAL";
  const result = await handle(
    request(value.body, value.environment),
    value.environment,
    Date.parse("2026-09-04T12:01:00Z"),
  );
  assert.equal(result.status, 503);
});

test("accepts the exact deterministic anchor emitted by the Go producer", async () => {
  const golden = JSON.parse(
    readFileSync(new URL("../../../testdata/wazuh-anchor-golden.json", import.meta.url), "utf8"),
  );
  assert.equal(golden.schema_version, 1);
  const bucket = new FakeBucket();
  const environment = {
    EXPECTED_HOSTNAME: "anchor.plntir.invalid",
    WAZUH_ANCHOR_VERIFY_KEY: golden.public_key,
    WAZUH_MTLS_CERT_SHA256: "a".repeat(64),
    WAZUH_ANCHORS: bucket,
  };
  const result = await handle(request(golden.body, environment), environment, Date.parse("2026-09-04T12:01:00Z"));
  assert.equal(result.status, 201);
});

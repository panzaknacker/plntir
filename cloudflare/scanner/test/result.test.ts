import { describe, expect, it } from "vitest";

import { type ScanJob } from "../src/model";
import { canonicalResultEnvelope, signScanResult, type ScanVerdict } from "../src/result";

function base64URL(value: Uint8Array): string {
  let raw = "";
  for (const byte of value) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function privateKeyPKCS8(key: CryptoKey): Promise<string> {
  const exported = await crypto.subtle.exportKey("pkcs8", key);
  if (!(exported instanceof ArrayBuffer)) {
    throw new Error("PKCS8 export did not return an ArrayBuffer");
  }
  return base64URL(new Uint8Array(exported));
}

const job: ScanJob = {
  account: "0123456789abcdef0123456789abcdef",
  action: "CompleteMultipartUpload",
  bucket: "plntir-files",
  objectKey: "objects/obj_0123456789abcdefghjkmnpqrstvwxyz",
  ciphertextSize: 80_000_000,
  eTag: "0123456789abcdef-2",
  eventTime: "2026-09-04T12:00:00Z",
  jobID: "scan_0123456789abcdefghjkmnpqrstvwxyz",
  fileVersionID: "fver_0123456789abcdefghjkmnpqrstvwxyz",
  mediaKind: "image",
  manifestSHA256: "a".repeat(64),
  kmsCiphertext: "AQIDBAUG",
  kmsCiphertextSHA256: "7".repeat(64),
  plaintextSize: 79_999_968,
  chunkSize: 64 * 1024 * 1024,
  noncePrefix: "CQgHBg",
  signedAt: "2026-09-04T11:55:00Z",
  signature: "A".repeat(86),
};

const verdict: ScanVerdict = {
  verdict: "clean",
  engineVersion: "clamav-qualified-1",
  ruleVersion: "rules-20260904",
  contentSHA256: "b".repeat(64),
  detectedType: "video/mp4",
  reason: "",
  scannedAt: "2026-09-04T12:10:00Z",
};

describe("signed scan result envelope", () => {
  it("produces an Ed25519 envelope verifiable from the exported public key", async () => {
    const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const result = await signScanResult(job, verdict, await privateKeyPKCS8(pair.privateKey));
    const unsigned = {
      version: result.version,
      kind: result.kind,
      source: result.source,
      sequence: result.sequence,
      timestamp: result.timestamp,
      deduplication_id: result.deduplication_id,
      payload: result.payload,
    };
    const signature = result.signature.replace(/-/g, "+").replace(/_/g, "/").padEnd(88, "=");
    const signatureBytes = Uint8Array.from(atob(signature), (character) => character.charCodeAt(0));
    await expect(
      crypto.subtle.verify({ name: "Ed25519" }, pair.publicKey, signatureBytes, canonicalResultEnvelope(unsigned)),
    ).resolves.toBe(true);
    expect(result.deduplication_id).toBe(job.jobID);
    expect(result.source).toBe(`scanner-${job.jobID}`);
  });

  it("refuses to sign an unlocking verdict without a complete content hash", async () => {
    const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    await expect(
      signScanResult(job, { ...verdict, contentSHA256: "" }, await privateKeyPKCS8(pair.privateKey)),
    ).rejects.toThrow("requires a SHA-256");
  });
});

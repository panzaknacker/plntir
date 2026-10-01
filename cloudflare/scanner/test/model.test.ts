import { describe, expect, it } from "vitest";
import goldenData from "../../../testdata/scanmeta-golden.json" with { type: "json" };

import { assertSealedEnvironment } from "../src/environment";
import {
  MIN_MEDIA_CHUNK_BYTES,
  parseObjectMetadata,
  parseR2Event,
  PermanentEventError,
  type ObjectMetadata,
  type R2EventNotification,
} from "../src/model";
import { canonicalMetadata, sha256Hex, verifyMetadataSignature } from "../src/signature";

interface GoldenVector {
  accountID: string;
  bucket: string;
  objectKey: string;
  ciphertextSize: number;
  jobID: string;
  fileVersionID: string;
  mediaKind: "standard" | "image" | "video";
  manifestSHA256: string;
  kmsCiphertext: string;
  kmsCiphertextSHA256: string;
  plaintextSize: number;
  chunkSize: number;
  noncePrefix: string;
  signedAt: string;
  publicKey: string;
  canonical: string;
  signature: string;
}

const golden = goldenData as GoldenVector;

const event: R2EventNotification = {
  account: "0123456789abcdef0123456789abcdef",
  action: "CompleteMultipartUpload",
  bucket: "plntir-files",
  object: {
    key: "objects/obj_0123456789abcdefghjkmnpqrstvwxyz",
    size: 80_000_000,
    eTag: "0123456789abcdef-2",
  },
  eventTime: "2026-09-04T12:00:00.000Z",
};

function base64URL(value: Uint8Array): string {
  let raw = "";
  for (const byte of value) {
    raw += String.fromCharCode(byte);
  }
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function signedFixture(): Promise<{
  metadata: ObjectMetadata;
  publicKey: string;
}> {
  const kmsCiphertext = new Uint8Array([1, 2, 3, 4, 5, 6]);
  const metadata: ObjectMetadata = {
    jobID: "scan_0123456789abcdefghjkmnpqrstvwxyz",
    fileVersionID: "fver_0123456789abcdefghjkmnpqrstvwxyz",
    mediaKind: "image",
    manifestSHA256: "a".repeat(64),
    kmsCiphertext: base64URL(kmsCiphertext),
    kmsCiphertextSHA256: await sha256Hex(kmsCiphertext),
    plaintextSize: 79_999_968,
    chunkSize: MIN_MEDIA_CHUNK_BYTES,
    noncePrefix: base64URL(new Uint8Array([9, 8, 7, 6])),
    signedAt: "2026-09-04T11:55:00Z",
    signature: base64URL(new Uint8Array(64)),
  };
  const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const signature = await crypto.subtle.sign({ name: "Ed25519" }, keys.privateKey, canonicalMetadata(event, metadata));
  metadata.signature = base64URL(new Uint8Array(signature));
  const exported = await crypto.subtle.exportKey("raw", keys.publicKey);
  if (!(exported instanceof ArrayBuffer)) {
    throw new Error("Ed25519 raw export did not return an ArrayBuffer");
  }
  return { metadata, publicKey: base64URL(new Uint8Array(exported)) };
}

function customMetadata(metadata: ObjectMetadata): Record<string, string> {
  return {
    "plntir-job-id": metadata.jobID,
    "plntir-file-version-id": metadata.fileVersionID,
    "plntir-media-kind": metadata.mediaKind,
    "plntir-manifest-sha256": metadata.manifestSHA256,
    "plntir-kms-ciphertext": metadata.kmsCiphertext,
    "plntir-kms-ciphertext-sha256": metadata.kmsCiphertextSHA256,
    "plntir-plaintext-size": String(metadata.plaintextSize),
    "plntir-chunk-size": String(metadata.chunkSize),
    "plntir-nonce-prefix": metadata.noncePrefix,
    "plntir-signed-at": metadata.signedAt,
    "plntir-signature": metadata.signature,
  };
}

describe("signed R2 scan metadata", () => {
  it("matches the shared Go/TypeScript golden vector", async () => {
    const goldenEvent: R2EventNotification = {
      account: golden.accountID,
      action: "CompleteMultipartUpload",
      bucket: golden.bucket,
      object: {
        key: golden.objectKey,
        size: golden.ciphertextSize,
        eTag: "0123456789abcdef-2",
      },
      eventTime: "2026-09-04T12:00:00Z",
    };
    const metadata: ObjectMetadata = {
      jobID: golden.jobID,
      fileVersionID: golden.fileVersionID,
      mediaKind: golden.mediaKind,
      manifestSHA256: golden.manifestSHA256,
      kmsCiphertext: golden.kmsCiphertext,
      kmsCiphertextSHA256: golden.kmsCiphertextSHA256,
      plaintextSize: golden.plaintextSize,
      chunkSize: golden.chunkSize,
      noncePrefix: golden.noncePrefix,
      signedAt: golden.signedAt,
      signature: golden.signature,
    };
    expect(new TextDecoder().decode(canonicalMetadata(goldenEvent, metadata))).toBe(golden.canonical);
    await expect(verifyMetadataSignature(goldenEvent, metadata, golden.publicKey)).resolves.toBeUndefined();
  });

  it("accepts a valid Ed25519-bound object", async () => {
    const fixture = await signedFixture();
    const parsedEvent = parseR2Event(event);
    const parsedMetadata = parseObjectMetadata(customMetadata(fixture.metadata));
    await expect(verifyMetadataSignature(parsedEvent, parsedMetadata, fixture.publicKey)).resolves.toBeUndefined();
  });

  it("rejects a changed object identity", async () => {
    const fixture = await signedFixture();
    const changed = {
      ...event,
      object: {
        ...event.object,
        key: "objects/obj_1123456789abcdefghjkmnpqrstvwxyz",
      },
    };
    await expect(verifyMetadataSignature(changed, fixture.metadata, fixture.publicKey)).rejects.toThrow(
      "signature is invalid",
    );
  });

  it("rejects undersized chunks for large media", async () => {
    const fixture = await signedFixture();
    const metadata = customMetadata({
      ...fixture.metadata,
      plaintextSize: 6_000_000_000,
      chunkSize: 8 * 1024 * 1024,
    });
    expect(() => parseObjectMetadata(metadata)).toThrow(PermanentEventError);
  });

  it("rejects delete events and user-derived object keys", () => {
    expect(() => parseR2Event({ ...event, action: "DeleteObject" })).toThrow(PermanentEventError);
    expect(() =>
      parseR2Event({
        ...event,
        object: { ...event.object, key: "objects/Alice/tax.pdf" },
      }),
    ).toThrow(PermanentEventError);
  });

  it("rejects non-canonical accounts, buckets, and signing times", async () => {
    expect(() => parseR2Event({ ...event, account: "not-an-account" })).toThrow(PermanentEventError);
    expect(() => parseR2Event({ ...event, bucket: "Invalid_Bucket" })).toThrow(PermanentEventError);
    const fixture = await signedFixture();
    expect(() =>
      parseObjectMetadata(
        customMetadata({
          ...fixture.metadata,
          signedAt: "2026-09-04T11:55:00.000Z",
        }),
      ),
    ).toThrow(PermanentEventError);
  });
});

describe("production seal", () => {
  it("fails closed on checked-in sentinels", () => {
    expect(() =>
      assertSealedEnvironment({
        EXPECTED_ACCOUNT_ID: "SET_AT_PRODUCTION_SEAL",
        EXPECTED_BUCKET: "plntir-files",
        CORE_EVENT_VERIFY_KEY: "SET_AT_PRODUCTION_SEAL",
        KMS_BROKER_URL: "https://kms-broker.invalid/v1/rewrap",
        RESULT_BROKER_URL: "https://scan-results.invalid/v1/results",
        RESULT_SIGNING_KEY_PKCS8: "SET_AT_PRODUCTION_SEAL",
      }),
    ).toThrow("not production-sealed");
  });

  it("accepts only complete unproxied mTLS configuration", () => {
    expect(() =>
      assertSealedEnvironment({
        EXPECTED_ACCOUNT_ID: event.account,
        EXPECTED_BUCKET: event.bucket,
        CORE_EVENT_VERIFY_KEY: base64URL(new Uint8Array(32).fill(7)),
        KMS_BROKER_URL: "https://kms-broker.security.example/v1/rewrap",
        RESULT_BROKER_URL: "https://result-broker.security.example/v1/results",
        RESULT_SIGNING_KEY_PKCS8: base64URL(new Uint8Array(48).fill(7)),
      }),
    ).not.toThrow();
  });
});

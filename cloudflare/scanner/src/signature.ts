import { decodeBase64URL, type ObjectMetadata, PermanentEventError, type R2EventNotification } from "./model";

const encoder = new TextEncoder();

export function canonicalMetadata(event: R2EventNotification, metadata: ObjectMetadata): Uint8Array {
  const fields = [
    "plntir-r2-scan-v1",
    event.account,
    event.bucket,
    event.object.key,
    String(event.object.size),
    metadata.jobID,
    metadata.fileVersionID,
    metadata.mediaKind,
    metadata.manifestSHA256,
    metadata.kmsCiphertextSHA256,
    String(metadata.plaintextSize),
    String(metadata.chunkSize),
    metadata.noncePrefix,
    metadata.signedAt,
  ];
  if (fields.some((field) => field.includes("\n") || field.includes("\r"))) {
    throw new PermanentEventError("signed metadata contains a line break");
  }
  return encoder.encode(`${fields.join("\n")}\n`);
}

export async function sha256Hex(value: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", value);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function verifyMetadataSignature(
  event: R2EventNotification,
  metadata: ObjectMetadata,
  publicKeyBase64URL: string,
): Promise<void> {
  const publicKey = await crypto.subtle.importKey(
    "raw",
    decodeBase64URL(publicKeyBase64URL, 32, "event verification key"),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    decodeBase64URL(metadata.signature, 64, "metadata signature"),
    canonicalMetadata(event, metadata),
  );
  if (!valid) {
    throw new PermanentEventError("object metadata signature is invalid");
  }
  const actualKMSHash = await sha256Hex(decodeBase64URL(metadata.kmsCiphertext, undefined, "KMS ciphertext", 1, 6144));
  if (actualKMSHash !== metadata.kmsCiphertextSHA256) {
    throw new PermanentEventError("KMS ciphertext hash does not match");
  }
}

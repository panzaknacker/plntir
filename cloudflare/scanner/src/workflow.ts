import { getContainer } from "@cloudflare/containers";
import { WorkflowEntrypoint, type WorkflowEvent, type WorkflowStep } from "cloudflare:workers";
import { NonRetryableError } from "cloudflare:workflows";

import { assertSealedEnvironment } from "./environment";
import { boundedJSON, requiredResponseInteger, requiredResponseString } from "./json";
import { revalidateScanJob } from "./job";
import { decodeBase64URL, PermanentEventError, type ScanJob } from "./model";
import { signScanResult, type ScanVerdict } from "./result";

interface KeyPreparation {
  sessionID: string;
  brokerPublicKey: string;
  wrapNonce: string;
  wrappedDEK: string;
}

export class ScanWorkflow extends WorkflowEntrypoint<CloudflareBindings, ScanJob> {
  override async run(event: Readonly<WorkflowEvent<ScanJob>>, step: WorkflowStep): Promise<ScanVerdict> {
    assertSealedEnvironment(this.env);
    const job = event.payload;

    await step.do(
      "verify immutable object",
      { retries: { limit: 5, delay: "30 seconds", backoff: "exponential" } },
      async () => {
        try {
          await revalidateScanJob(job, this.env);
        } catch (error) {
          if (error instanceof PermanentEventError) {
            throw new NonRetryableError(error.message, "InvalidSignedScanJob");
          }
          throw error;
        }
        return { verified: true };
      },
    );

    const verdict = await step.do<ScanVerdict>(
      "stream decrypt and scan",
      {
        retries: { limit: 2, delay: "5 minutes", backoff: "exponential" },
        timeout: "7 days",
      },
      async () => this.scan(job),
    );

    await step.do(
      "deliver signed result",
      { retries: { limit: 20, delay: "1 minute", backoff: "exponential" } },
      async () => {
        const signedResult = await signScanResult(
          job,
          verdict,
          (this.env as CloudflareBindings & { RESULT_SIGNING_KEY_PKCS8: string }).RESULT_SIGNING_KEY_PKCS8,
        );
        const response = await this.env.RESULT_BROKER_MTLS.fetch(this.env.RESULT_BROKER_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Idempotency-Key": job.jobID,
          },
          body: JSON.stringify(signedResult),
        });
        if (!response.ok) {
          throw new Error(`result broker returned ${response.status}`);
        }
        return { delivered: true };
      },
    );
    return verdict;
  }

  private async scan(job: ScanJob): Promise<ScanVerdict> {
    const container = getContainer(this.env.SCANNERS, job.jobID);
    const preparation = await this.prepareKey(container, job);
    const object = await this.env.FILES.get(job.objectKey);
    if (object === null || object.body === null) {
      throw new Error("R2 object disappeared before scan");
    }
    if (object.size !== job.ciphertextSize || object.etag !== job.eTag) {
      throw new NonRetryableError("R2 object changed after signed validation", "ImmutableObjectChanged");
    }
    const response = await container.fetch(
      new Request("http://scanner.internal/v1/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/octet-stream",
          "X-Plntir-Job-ID": job.jobID,
          "X-Plntir-File-Version-ID": job.fileVersionID,
          "X-Plntir-Object-Key": job.objectKey,
          "X-Plntir-Media-Kind": job.mediaKind,
          "X-Plntir-Manifest-SHA256": job.manifestSHA256,
          "X-Plntir-Plaintext-Size": String(job.plaintextSize),
          "X-Plntir-Chunk-Size": String(job.chunkSize),
          "X-Plntir-Nonce-Prefix": job.noncePrefix,
          "X-Plntir-Scan-Session": preparation.sessionID,
          "X-Plntir-Broker-Public-Key": preparation.brokerPublicKey,
          "X-Plntir-Wrap-Nonce": preparation.wrapNonce,
          "X-Plntir-Wrapped-DEK": preparation.wrappedDEK,
        },
        body: object.body,
      }),
    );
    const value = await boundedJSON(response);
    const verdict = requiredResponseString(value, "verdict", 32);
    if (verdict !== "clean" && verdict !== "malware" && verdict !== "unscannable") {
      throw new Error("scanner returned an invalid verdict");
    }
    if (!response.ok && verdict !== "unscannable") {
      throw new Error(`scanner returned ${response.status}`);
    }
    const contentSHA256 = optionalResponseString(value, "content_sha256", 64);
    if ((verdict === "clean" || verdict === "malware") && !/^[a-f0-9]{64}$/.test(contentSHA256)) {
      throw new Error("scanner verdict lacks a complete content hash");
    }
    return {
      verdict,
      engineVersion: requiredResponseString(value, "engine_version", 256),
      ruleVersion: optionalResponseString(value, "rule_version", 256),
      contentSHA256,
      detectedType: optionalResponseString(value, "detected_type", 256),
      reason: optionalResponseString(value, "reason", 1024),
      scannedAt: new Date().toISOString(),
    };
  }

  private async prepareKey(container: DurableObjectStub, job: ScanJob): Promise<KeyPreparation> {
    const prepareResponse = await container.fetch(
      new Request("http://scanner.internal/v1/prepare", { method: "POST" }),
    );
    if (!prepareResponse.ok) {
      throw new Error(`scanner key preparation returned ${prepareResponse.status}`);
    }
    const prepared = await boundedJSON(prepareResponse);
    const sessionID = requiredResponseString(prepared, "session_id", 64);
    const containerPublicKey = requiredResponseString(prepared, "public_key", 64);
    decodeBase64URL(containerPublicKey, 32, "container public key");

    const brokerResponse = await this.env.KMS_BROKER_MTLS.fetch(this.env.KMS_BROKER_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Idempotency-Key": job.jobID,
      },
      body: JSON.stringify({
        envelope_version: 1,
        job,
        scan_session_id: sessionID,
        container_public_key: containerPublicKey,
      }),
    });
    if (!brokerResponse.ok) {
      throw new Error(`KMS broker returned ${brokerResponse.status}`);
    }
    const wrapped = await boundedJSON(brokerResponse);
    if (
      requiredResponseInteger(wrapped, "envelope_version") !== 1 ||
      requiredResponseString(wrapped, "job_id", 64) !== job.jobID ||
      requiredResponseString(wrapped, "scan_session_id", 64) !== sessionID
    ) {
      throw new Error("KMS broker response does not match scan session");
    }
    const brokerPublicKey = requiredResponseString(wrapped, "broker_public_key", 64);
    const wrapNonce = requiredResponseString(wrapped, "wrap_nonce", 32);
    const wrappedDEK = requiredResponseString(wrapped, "wrapped_dek", 128);
    decodeBase64URL(brokerPublicKey, 32, "broker public key");
    decodeBase64URL(wrapNonce, 12, "key-wrap nonce");
    decodeBase64URL(wrappedDEK, 48, "wrapped DEK");
    return { sessionID, brokerPublicKey, wrapNonce, wrappedDEK };
  }
}

function optionalResponseString(value: unknown, field: string, maximumLength: number): string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("upstream response is not an object");
  }
  const candidate = (value as Record<string, unknown>)[field];
  if (candidate === undefined) {
    return "";
  }
  if (typeof candidate !== "string" || candidate.length > maximumLength) {
    throw new Error(`upstream response has invalid ${field}`);
  }
  return candidate;
}

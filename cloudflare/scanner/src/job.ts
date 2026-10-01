import {
  parseObjectMetadata,
  parseR2Event,
  PermanentEventError,
  type R2EventNotification,
  type ScanJob,
} from "./model";
import { verifyMetadataSignature } from "./signature";

interface JobEnvironment {
  EXPECTED_ACCOUNT_ID: string;
  EXPECTED_BUCKET: string;
  CORE_EVENT_VERIFY_KEY: string;
  FILES: R2Bucket;
}

export async function loadScanJob(body: unknown, environment: JobEnvironment): Promise<ScanJob> {
  const event = parseR2Event(body);
  if (event.account !== environment.EXPECTED_ACCOUNT_ID || event.bucket !== environment.EXPECTED_BUCKET) {
    throw new PermanentEventError("event account or bucket does not match binding");
  }
  const head = await environment.FILES.head(event.object.key);
  if (head === null) {
    throw new Error("notified R2 object is not readable yet");
  }
  if (head.size !== event.object.size || head.etag !== event.object.eTag) {
    throw new PermanentEventError("R2 event does not match immutable object head");
  }
  const metadata = parseObjectMetadata(head.customMetadata);
  checkTimes(event, metadata.signedAt);
  if (event.object.size < metadata.plaintextSize) {
    throw new PermanentEventError("ciphertext is smaller than declared plaintext");
  }
  await verifyMetadataSignature(event, metadata, environment.CORE_EVENT_VERIFY_KEY);
  return {
    ...metadata,
    account: event.account,
    action: event.action as "PutObject" | "CompleteMultipartUpload",
    bucket: event.bucket,
    objectKey: event.object.key,
    ciphertextSize: event.object.size,
    eTag: event.object.eTag,
    eventTime: event.eventTime,
  };
}

export async function revalidateScanJob(job: ScanJob, environment: JobEnvironment): Promise<void> {
  const event = eventFromJob(job);
  if (event.account !== environment.EXPECTED_ACCOUNT_ID || event.bucket !== environment.EXPECTED_BUCKET) {
    throw new PermanentEventError("workflow account or bucket does not match binding");
  }
  const metadata = parseObjectMetadata({
    "plntir-job-id": job.jobID,
    "plntir-file-version-id": job.fileVersionID,
    "plntir-media-kind": job.mediaKind,
    "plntir-manifest-sha256": job.manifestSHA256,
    "plntir-kms-ciphertext": job.kmsCiphertext,
    "plntir-kms-ciphertext-sha256": job.kmsCiphertextSHA256,
    "plntir-plaintext-size": String(job.plaintextSize),
    "plntir-chunk-size": String(job.chunkSize),
    "plntir-nonce-prefix": job.noncePrefix,
    "plntir-signed-at": job.signedAt,
    "plntir-signature": job.signature,
  });
  checkTimes(event, metadata.signedAt);
  await verifyMetadataSignature(event, metadata, environment.CORE_EVENT_VERIFY_KEY);
  const head = await environment.FILES.head(job.objectKey);
  if (head === null || head.size !== job.ciphertextSize || head.etag !== job.eTag) {
    throw new Error("workflow object no longer matches its signed event");
  }
}

export function eventFromJob(job: ScanJob): R2EventNotification {
  return parseR2Event({
    account: job.account,
    action: job.action,
    bucket: job.bucket,
    object: {
      key: job.objectKey,
      size: job.ciphertextSize,
      eTag: job.eTag,
    },
    eventTime: job.eventTime,
  });
}

function checkTimes(event: R2EventNotification, signedAt: string): void {
  const eventTime = Date.parse(event.eventTime);
  const signatureTime = Date.parse(signedAt);
  const difference = eventTime - signatureTime;
  if (difference < -5 * 60 * 1000 || difference > 48 * 60 * 60 * 1000) {
    throw new PermanentEventError("metadata signature is outside the upload window");
  }
}

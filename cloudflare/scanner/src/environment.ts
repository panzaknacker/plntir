import { decodeBase64URL } from "./model";

interface RuntimeConfiguration {
  EXPECTED_ACCOUNT_ID: string;
  EXPECTED_BUCKET: string;
  CORE_EVENT_VERIFY_KEY: string;
  KMS_BROKER_URL: string;
  RESULT_BROKER_URL: string;
  RESULT_SIGNING_KEY_PKCS8?: string;
}

const ACCOUNT_ID = /^[a-f0-9]{32}$/;
const BUCKET = /^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/;

export function assertSealedEnvironment(configuration: RuntimeConfiguration): void {
  if (!ACCOUNT_ID.test(configuration.EXPECTED_ACCOUNT_ID)) {
    throw new Error("scanner account binding is not production-sealed");
  }
  if (!BUCKET.test(configuration.EXPECTED_BUCKET)) {
    throw new Error("scanner bucket binding is invalid");
  }
  decodeBase64URL(configuration.CORE_EVENT_VERIFY_KEY, 32, "event verification key");
  validateBrokerURL(configuration.KMS_BROKER_URL, "KMS broker");
  validateBrokerURL(configuration.RESULT_BROKER_URL, "result broker");
  if (typeof configuration.RESULT_SIGNING_KEY_PKCS8 !== "string") {
    throw new Error("result signing key secret is missing");
  }
  decodeBase64URL(configuration.RESULT_SIGNING_KEY_PKCS8, undefined, "result signing key", 40, 128);
}

function validateBrokerURL(raw: string, label: string): void {
  let value: URL;
  try {
    value = new URL(raw);
  } catch {
    throw new Error(`${label} URL is invalid`);
  }
  if (
    value.protocol !== "https:" ||
    value.username !== "" ||
    value.password !== "" ||
    value.hash !== "" ||
    value.hostname.endsWith(".invalid") ||
    value.hostname === "plntir.example" ||
    value.hostname.endsWith(".plntir.example")
  ) {
    throw new Error(`${label} must be an unproxied HTTPS mTLS origin`);
  }
}

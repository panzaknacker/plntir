export interface JSONResult {
  value: unknown;
  mode: string;
}

export class HTTPProblem extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "HTTPProblem";
    this.status = status;
    this.code = code;
  }
}

export async function fetchJSON(path: string, signal?: AbortSignal): Promise<JSONResult> {
  if (!path.startsWith("/api/v1/") || path.includes("//")) {
    throw new Error("API path is outside the same-origin v1 boundary");
  }
  const response = await fetch(path, {
    cache: "no-store",
    credentials: "same-origin",
    headers: { Accept: "application/json, application/problem+json" },
    method: "GET",
    redirect: "error",
    signal,
  });
  const value = await boundedJSON(response);
  if (!response.ok) {
    const record = asRecord(value);
    const code = typeof record.code === "string" ? record.code : "request_failed";
    const title = typeof record.title === "string" ? record.title : `HTTP ${response.status}`;
    throw new HTTPProblem(response.status, code, title);
  }
  return { value, mode: response.headers.get("X-Plntir-Mode") ?? "unknown" };
}

async function boundedJSON(response: Response, maximumBytes = 1024 * 1024): Promise<unknown> {
  const contentType = response.headers.get("Content-Type") ?? "";
  if (!/^application\/(?:json|problem\+json)(?:\s*;|$)/i.test(contentType)) {
    throw new HTTPProblem(response.status || 502, "invalid_content_type", "Die API-Antwort war kein JSON.");
  }
  const declared = Number(response.headers.get("Content-Length") ?? "0");
  if (Number.isFinite(declared) && declared > maximumBytes) {
    throw new HTTPProblem(502, "response_too_large", "Die API-Antwort war zu groß.");
  }
  if (response.body === null) {
    throw new HTTPProblem(502, "empty_response", "Die API-Antwort war leer.");
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let text = "";
  let size = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) {
        text += decoder.decode();
        break;
      }
      size += chunk.value.byteLength;
      if (size > maximumBytes) {
        await reader.cancel("bounded response exceeded");
        throw new HTTPProblem(502, "response_too_large", "Die API-Antwort war zu groß.");
      }
      text += decoder.decode(chunk.value, { stream: true });
    }
    return JSON.parse(text) as unknown;
  } catch (error) {
    if (error instanceof HTTPProblem) throw error;
    throw new HTTPProblem(502, "invalid_json", "Die API-Antwort war beschädigt.");
  }
}

export function asRecord(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Erwartetes API-Objekt fehlt.");
  }
  return value as Record<string, unknown>;
}

export function requiredString(record: Record<string, unknown>, field: string, maximum = 1024): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new Error(`Ungültiges API-Feld: ${field}`);
  }
  return value;
}

export function requiredInteger(record: Record<string, unknown>, field: string, minimum = 0): number {
  const value = record[field];
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    throw new Error(`Ungültiges API-Feld: ${field}`);
  }
  return value as number;
}

export function requiredArray(record: Record<string, unknown>, field: string, maximum: number): unknown[] {
  const value = record[field];
  if (!Array.isArray(value) || value.length > maximum) {
    throw new Error(`Ungültiges API-Feld: ${field}`);
  }
  return value;
}

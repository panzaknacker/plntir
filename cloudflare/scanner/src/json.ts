export async function boundedJSON(response: Response, maximumBytes = 32 * 1024): Promise<unknown> {
  const declaredLength = response.headers.get("Content-Length");
  if (declaredLength !== null && Number(declaredLength) > maximumBytes) {
    throw new Error("upstream JSON response is oversized");
  }
  if (response.body === null) {
    throw new Error("upstream JSON response has no body");
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let bytes = 0;
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) {
      text += decoder.decode();
      break;
    }
    bytes += chunk.value.byteLength;
    if (bytes > maximumBytes) {
      await reader.cancel("response size limit exceeded");
      throw new Error("upstream JSON response is oversized");
    }
    text += decoder.decode(chunk.value, { stream: true });
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error("upstream returned invalid JSON");
  }
}

export function requiredResponseString(value: unknown, field: string, maximumLength: number): string {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`upstream response lacks ${field}`);
  }
  const result = (value as Record<string, unknown>)[field];
  if (typeof result !== "string" || result.length === 0 || result.length > maximumLength) {
    throw new Error(`upstream response has invalid ${field}`);
  }
  return result;
}

export function requiredResponseInteger(value: unknown, field: string): number {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`upstream response lacks ${field}`);
  }
  const result = (value as Record<string, unknown>)[field];
  if (!Number.isSafeInteger(result)) {
    throw new Error(`upstream response has invalid ${field}`);
  }
  return result as number;
}

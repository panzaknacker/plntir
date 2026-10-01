import { Container } from "@cloudflare/containers";

export class ScannerContainer extends Container<CloudflareBindings> {
  override defaultPort = 8080;
  override sleepAfter = "5m";
  override enableInternet = false;
  override envVars = {
    PLNTIR_SCANNER_MODE: "shadow-fail-closed",
  };

  override onStart(): void {
    console.log(JSON.stringify({ event: "scanner_container_start" }));
  }

  override onStop(parameters: { exitCode: number; reason: "exit" | "runtime_signal" }): void {
    console.log(
      JSON.stringify({
        event: "scanner_container_stop",
        exit_code: parameters.exitCode,
        reason: parameters.reason,
      }),
    );
  }

  override onError(error: unknown): void {
    console.error(
      JSON.stringify({
        event: "scanner_container_error",
        error_type: error instanceof Error ? error.name : "unknown",
      }),
    );
  }
}

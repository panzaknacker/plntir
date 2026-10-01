import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it, vi } from "vitest";
import { HTTPProblem } from "../../shared/http";
import statusFixture from "../../../api/fixtures/fileshare-status-shadow.json";
import { App, loadFileshare, type LoadedFileshare } from "../src/app";
import { parseFiles, parseSession } from "../src/model";
import { filesFixture, sessionFixture } from "./fixtures";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("fileshare", () => {
  const loaded: LoadedFileshare = {
    state: "ready",
    session: parseSession(sessionFixture),
    page: parseFiles(filesFixture),
    apiMode: "shadow",
  };

  it("shows fixture file states without enabling unfinished transfers", async () => {
    render(<App loader={async () => loaded} />);
    await waitFor(() => expect(screen.getByText("Bericht.pdf")).toBeInTheDocument());
    expect(screen.getByText("Malware")).toBeInTheDocument();
    expect(screen.queryByLabelText("Datei auswählen")).not.toBeInTheDocument();
    for (const button of screen.getAllByRole("button", { name: "Herunterladen" })) expect(button).toBeDisabled();
  });

  it("loads the Core availability contract without requesting unimplemented routes", async () => {
    const fetch = vi.fn().mockResolvedValue(statusResponse());
    vi.stubGlobal("fetch", fetch);
    render(<App />);
    await waitFor(() => expect(screen.getByText("Fileshare ist noch nicht verfügbar.")).toBeInTheDocument());
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByText("Noch keine Dateien")).not.toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith(
      "/api/v1/fileshare/status",
      expect.objectContaining({ credentials: "same-origin", redirect: "error", method: "GET" }),
    );
  });

  it.each([null, "unknown", "active"])("rejects unsupported API mode %s", async (mode) => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(statusResponse(mode)));
    await expect(loadFileshare()).rejects.toThrow("Unbekannter Fileshare-Status.");
  });

  it("does not turn an unknown availability state into an empty file list", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(statusResponse("shadow", { state: "available" })));
    await expect(loadFileshare()).rejects.toThrow("Unbekannter Fileshare-Status.");
  });

  it("reports revoked Access instead of preserving a successful status", async () => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(statusResponse())
      .mockResolvedValueOnce(new Response(JSON.stringify({ title: "Access required" }), {
        status: 401,
        headers: { "Content-Type": "application/problem+json", "X-Plntir-Mode": "shadow" },
      }));
    vi.stubGlobal("fetch", fetch);
    render(<App />);
    await waitFor(() => expect(screen.getByText("Fileshare ist noch nicht verfügbar.")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Aktualisieren" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Cloudflare-Access-Anmeldung"));
    expect(screen.queryByText("Fileshare ist noch nicht verfügbar.")).not.toBeInTheDocument();
    expect(screen.queryByText("Noch keine Dateien")).not.toBeInTheDocument();
  });

  it("discards a late response after changing the loader", async () => {
    let resolveFirst!: (result: LoadedFileshare) => void;
    let firstSignal: AbortSignal | undefined;
    const first = (signal?: AbortSignal) => {
      firstSignal = signal;
      return new Promise<LoadedFileshare>((resolve) => { resolveFirst = resolve; });
    };
    const unavailable = async (): Promise<LoadedFileshare> => ({ state: "unavailable", apiMode: "shadow" });
    const view = render(<App loader={first} />);
    await waitFor(() => expect(firstSignal).toBeDefined());
    view.rerender(<App loader={unavailable} />);
    await waitFor(() => expect(screen.getByText("Fileshare ist noch nicht verfügbar.")).toBeInTheDocument());
    expect(firstSignal?.aborted).toBe(true);
    await act(async () => { resolveFirst(loaded); });
    expect(screen.queryByText("Bericht.pdf")).not.toBeInTheDocument();
    expect(screen.getByText("Fileshare ist noch nicht verfügbar.")).toBeInTheDocument();
  });

  it("clears previously loaded files when refresh loses authentication", async () => {
    const loader = vi.fn()
      .mockResolvedValueOnce(loaded)
      .mockRejectedValueOnce(new HTTPProblem(401, "access_required", "Access required"));
    render(<App loader={loader} />);
    await waitFor(() => expect(screen.getByText("Bericht.pdf")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Aktualisieren" }));
    await waitFor(() => expect(screen.getByRole("alert")).toBeInTheDocument());
    expect(screen.queryByText("Bericht.pdf")).not.toBeInTheDocument();
  });

  it("keeps downloads disabled even when a preview loader claims active mode", async () => {
    render(<App loader={async () => ({ ...loaded, apiMode: "active" })} />);
    await waitFor(() => expect(screen.getByText("Bericht.pdf")).toBeInTheDocument());
    for (const button of screen.getAllByRole("button", { name: "Herunterladen" })) expect(button).toBeDisabled();
    expect(screen.queryByLabelText("Datei auswählen")).not.toBeInTheDocument();
  });

  it("filters locally without exposing a directory", async () => {
    render(<App loader={async () => loaded} />);
    await waitFor(() => expect(screen.getByText("Fund.bin")).toBeInTheDocument());
    fireEvent.input(screen.getByLabelText("Dateien filtern"), { target: { value: "bericht" } });
    expect(screen.getByText("Bericht.pdf")).toBeInTheDocument();
    expect(screen.queryByText("Fund.bin")).not.toBeInTheDocument();
  });

  it("rejects unknown scan states and oversized pages", () => {
    expect(() => parseFiles({ items: [{ ...filesFixture.items[0], scan_state: "trusted" }] })).toThrow();
    expect(() => parseFiles({ items: Array.from({ length: 1_001 }, () => filesFixture.items[0]) })).toThrow();
  });
});

function statusResponse(mode: string | null = "shadow", value: unknown = statusFixture): Response {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (mode !== null) headers.set("X-Plntir-Mode", mode);
  return new Response(JSON.stringify(value), { headers });
}

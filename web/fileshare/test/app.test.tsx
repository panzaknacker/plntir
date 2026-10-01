import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "../src/app";
import { parseFiles, parseSession } from "../src/model";
import { filesFixture, sessionFixture } from "./fixtures";

afterEach(cleanup);

describe("fileshare", () => {
  const loaded = { session: parseSession(sessionFixture), page: parseFiles(filesFixture), apiMode: "shadow" };

  it("shows real file states while all actions stay disabled in shadow mode", async () => {
    render(<App loader={async () => loaded} />);
    await waitFor(() => expect(screen.getByText("Bericht.pdf")).toBeInTheDocument());
    expect(screen.getByText("Malware")).toBeInTheDocument();
    expect(screen.getByLabelText("Datei auswählen")).toBeDisabled();
    for (const button of screen.getAllByRole("button", { name: "Herunterladen" })) expect(button).toBeDisabled();
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

import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/preact";
import { afterEach, describe, expect, it } from "vitest";
import { App } from "../src/app";
import { parseHealth } from "../src/model";
import { healthFixture } from "./fixtures";

afterEach(cleanup);

describe("admin dashboard", () => {
  it("renders measured legacy state without inventing native claims", async () => {
    render(<App loader={async () => ({ projection: parseHealth(healthFixture), apiMode: "shadow" })} />);
    expect(screen.getByText("Status wird geladen")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Managed Mac")).toBeInTheDocument());
    expect(screen.getByText("Shadow · nur lesen")).toBeInTheDocument();
    expect(screen.getByText("Legacy v2")).toBeInTheDocument();
    expect(screen.getAllByText("Noch nicht gemessen").length).toBeGreaterThan(0);
    expect(screen.queryByText("Alles sicher")).not.toBeInTheDocument();
  });

  it("keeps a clear error state", async () => {
    render(
      <App
        loader={async () => {
          throw new Error("offline");
        }}
      />,
    );
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("nicht vertragskonform"));
    expect(screen.getByText("Noch kein Status")).toBeInTheDocument();
  });

  it("rejects unknown state values and excess devices", () => {
    expect(() =>
      parseHealth({ ...healthFixture, services: [{ ...healthFixture.services[0], state: "perfect" }] }),
    ).toThrow();
    expect(() =>
      parseHealth({ ...healthFixture, devices: Array.from({ length: 26 }, () => healthFixture.devices[0]) }),
    ).toThrow();
  });
});

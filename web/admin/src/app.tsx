import { useCallback, useEffect, useState } from "preact/hooks";
import { fetchJSON, HTTPProblem } from "../../shared/http";
import { formatTime } from "../../shared/format";
import { type HealthProjection, parseHealth } from "./model";

export interface LoadedHealth {
  projection: HealthProjection;
  apiMode: string;
}

export type HealthLoader = (signal?: AbortSignal) => Promise<LoadedHealth>;

export async function loadHealth(signal?: AbortSignal): Promise<LoadedHealth> {
  const result = await fetchJSON("/api/v1/admin/health", signal);
  return { projection: parseHealth(result.value), apiMode: result.mode };
}

interface AppProps {
  loader?: HealthLoader;
}

export function App({ loader = loadHealth }: AppProps) {
  const [data, setData] = useState<LoadedHealth | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      setRefreshing(true);
      setError(null);
      try {
        setData(await loader(signal));
      } catch (reason) {
        if (signal?.aborted) return;
        setError(friendlyError(reason));
      } finally {
        if (!signal?.aborted) setRefreshing(false);
      }
    },
    [loader],
  );

  useEffect(() => {
    const controller = new AbortController();
    void refresh(controller.signal);
    return () => controller.abort();
  }, [refresh]);

  const projection = data?.projection ?? null;
  const readonly = data?.apiMode !== "active" || projection?.source.mode === "legacy-read-only";

  return (
    <div class="app-shell">
      <a class="skip-link" href="#main">
        Zum Inhalt
      </a>
      <header class="topbar">
        <div class="brand">
          <strong>Plntir</strong>
          <span>Administration</span>
        </div>
        <span class={`status ${readonly ? "status-warning" : "status-ok"}`}>
          {readonly ? "Shadow · nur lesen" : "Aktiv"}
        </span>
      </header>
      <main class="page" id="main">
        <div class="page-heading">
          <div>
            <h1>Betriebsübersicht</h1>
            <p class="lede">Gemessener Zustand von Diensten, Geräten, Sicherungen und Sicherheitsereignissen.</p>
          </div>
          <button class="primary-action" type="button" disabled={refreshing} onClick={() => void refresh()}>
            {refreshing ? "Wird aktualisiert …" : "Status aktualisieren"}
          </button>
        </div>

        {readonly && (
          <div class="notice" role="status">
            <p>
              <strong>Keine Änderungen möglich.</strong> Diese Ansicht läuft im Shadow-Modus oder zeigt eine
              Legacy-Projektion. Bestehende Systeme bleiben unverändert.
            </p>
          </div>
        )}
        {error && (
          <div class="error-panel" role="alert">
            <p>
              <strong>Status konnte nicht geladen werden.</strong> {error}
            </p>
            {data && <p>Die zuletzt erfolgreich geladenen Werte bleiben sichtbar.</p>}
          </div>
        )}

        {!projection ? (
          refreshing ? (
            <Loading />
          ) : (
            <Empty
              title="Noch kein Status"
              detail="Sobald die geschützte Health-API erreichbar ist, erscheinen hier Messwerte."
            />
          )
        ) : (
          <Dashboard projection={projection} />
        )}
      </main>
    </div>
  );
}

function Dashboard({ projection }: { projection: HealthProjection }) {
  const healthy = projection.services.filter((service) => service.state === "healthy").length;
  const verified = projection.devices.filter((device) => device.management === "verified").length;
  const openIncidents = projection.incidents.filter((incident) => incident.state !== "resolved").length;
  return (
    <>
      <section class="section" aria-labelledby="summary-title">
        <div class="section-heading">
          <h2 id="summary-title">Zusammenfassung</h2>
          <span class="meta">Stand {formatTime(projection.collectedAt)}</span>
        </div>
        <dl class="summary-list">
          <div>
            <dt>Gesunde Dienste</dt>
            <dd>
              {projection.services.length === 0 ? "Noch nicht gemessen" : `${healthy} / ${projection.services.length}`}
            </dd>
          </div>
          <div>
            <dt>MDM verifiziert</dt>
            <dd>
              {projection.devices.length === 0 ? "Noch nicht gemessen" : `${verified} / ${projection.devices.length}`}
            </dd>
          </div>
          <div>
            <dt>Offene Incidents</dt>
            <dd>{openIncidents}</dd>
          </div>
          <div>
            <dt>Statusquelle</dt>
            <dd class="summary-text">
              {projection.source.mode === "legacy-read-only"
                ? `Legacy v${projection.source.schemaVersion}`
                : "Plntir v3"}
            </dd>
          </div>
        </dl>
      </section>

      <section class="section" aria-labelledby="services-title">
        <div class="section-heading">
          <h2 id="services-title">Dienste</h2>
          <span class="meta">{projection.services.length} gemeldet</span>
        </div>
        {projection.services.length === 0 ? (
          <Empty title="Keine Dienstmessung" detail="Die Quelle hat noch keine Dienste gemeldet." />
        ) : (
          <div class="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Dienst</th>
                  <th>Zustand</th>
                  <th>Beobachtet</th>
                  <th>Hinweis</th>
                </tr>
              </thead>
              <tbody>
                {projection.services.map((service) => (
                  <tr key={service.id}>
                    <td>
                      <strong>{service.kind}</strong>
                      <br />
                      <span class="identifier meta">{service.id}</span>
                    </td>
                    <td>
                      <Status value={service.state} />
                    </td>
                    <td>{service.observedAt ? formatTime(service.observedAt) : "Noch nicht gemessen"}</td>
                    <td>{service.detail ?? "–"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section class="section" aria-labelledby="devices-title">
        <div class="section-heading">
          <h2 id="devices-title">Geräte</h2>
          <span class="meta">{projection.devices.length} von 25</span>
        </div>
        {projection.devices.length === 0 ? (
          <Empty title="Keine Geräte" detail="Es wurden noch keine Geräte in die v3-Projektion aufgenommen." />
        ) : (
          <div class="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Gerät</th>
                  <th>Management</th>
                  <th>Posture</th>
                  <th>Telemetrie</th>
                  <th>Backup</th>
                  <th>Wipe</th>
                  <th>Sensoren</th>
                </tr>
              </thead>
              <tbody>
                {projection.devices.map((device) => (
                  <tr key={device.id}>
                    <td>
                      <strong>{device.displayName}</strong>
                      <br />
                      <span class="meta">{platformLabel(device.platform)}</span>
                      <br />
                      <span class="identifier meta">{device.id}</span>
                    </td>
                    <td>
                      <Status value={device.management} />
                    </td>
                    <td>
                      <Status value={device.posture} />
                    </td>
                    <td>
                      <Status value={device.telemetry} />
                      {device.lastSeenAt && (
                        <>
                          <br />
                          <span class="meta">{formatTime(device.lastSeenAt)}</span>
                        </>
                      )}
                    </td>
                    <td>
                      <Status value={device.backup} />
                    </td>
                    <td>
                      <Status value={device.wipe} />
                    </td>
                    <td>{device.sensorSummary}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section class="section" aria-labelledby="incidents-title">
        <div class="section-heading">
          <h2 id="incidents-title">Incidents</h2>
          <span class="meta">{openIncidents} offen</span>
        </div>
        {projection.incidents.length === 0 ? (
          <Empty
            title="Keine Incidents gemeldet"
            detail="Die Statusquelle enthält derzeit keine Sicherheitsereignisse."
          />
        ) : (
          <div class="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Zeit</th>
                  <th>Schwere</th>
                  <th>Status</th>
                  <th>Ereignis</th>
                  <th>Gerät</th>
                </tr>
              </thead>
              <tbody>
                {projection.incidents.map((incident) => (
                  <tr key={incident.id}>
                    <td>{formatTime(incident.occurredAt)}</td>
                    <td>
                      <Status value={incident.severity} />
                    </td>
                    <td>
                      <Status value={incident.state} />
                    </td>
                    <td>
                      <strong>{incident.kind}</strong>
                      <br />
                      {incident.summary}
                      <br />
                      <span class="identifier meta">{incident.id}</span>
                    </td>
                    <td class="identifier">{incident.deviceId ?? "–"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section class="section" aria-labelledby="budgets-title">
        <div class="section-heading">
          <h2 id="budgets-title">Budget-Gates</h2>
          <span class="meta">Messwerte werden nicht geschätzt</span>
        </div>
        <dl class="summary-list">
          <div>
            <dt>AWS · Limit {projection.budgets.awsMonthlyLimitUSD} USD</dt>
            <dd>
              <Status value={projection.budgets.awsState} />
            </dd>
          </div>
          <div>
            <dt>Cloudflare · Limit {projection.budgets.cloudflareMonthlyLimitUSD} USD</dt>
            <dd>
              <Status value={projection.budgets.cloudflareState} />
            </dd>
          </div>
        </dl>
      </section>
    </>
  );
}

function Loading() {
  return (
    <section class="section" aria-live="polite" aria-busy="true">
      <h2>Status wird geladen</h2>
      <div class="loading-lines">
        <div class="loading-line" />
        <div class="loading-line" />
      </div>
    </section>
  );
}

function Empty({ title, detail }: { title: string; detail: string }) {
  return (
    <div class="empty-state">
      <p>
        <strong>{title}</strong>
      </p>
      <p>{detail}</p>
    </div>
  );
}

function Status({ value }: { value: string }) {
  const danger = ["unavailable", "failing", "failed", "blocked", "critical", "high"].includes(value);
  const ok = ["healthy", "verified", "passing", "fresh", "ok", "resolved", "full"].includes(value);
  return (
    <span class={`status ${danger ? "status-danger" : ok ? "status-ok" : "status-warning"}`}>{statusLabel(value)}</span>
  );
}

function statusLabel(value: string): string {
  const labels: Record<string, string> = {
    healthy: "Gesund",
    degraded: "Eingeschränkt",
    unavailable: "Nicht verfügbar",
    unknown: "Noch nicht gemessen",
    verified: "Verifiziert",
    partial: "Teilweise",
    passing: "Bestanden",
    failing: "Fehlgeschlagen",
    fresh: "Aktuell",
    stale: "Veraltet",
    running: "Läuft",
    paused: "Pausiert",
    failed: "Fehlgeschlagen",
    unverified: "Nicht verifiziert",
    ok: "Im Rahmen",
    warning: "Warnung",
    blocked: "Gesperrt",
    info: "Info",
    low: "Niedrig",
    medium: "Mittel",
    high: "Hoch",
    critical: "Kritisch",
    open: "Offen",
    acknowledged: "Bestätigt",
    resolved: "Gelöst",
  };
  return labels[value] ?? value;
}

function platformLabel(value: string): string {
  return value === "macos" ? "macOS" : value === "ios" ? "iOS" : "Linux";
}

function friendlyError(reason: unknown): string {
  if (reason instanceof HTTPProblem && reason.status === 401)
    return "Cloudflare-Access-Anmeldung oder Gerätefreigabe fehlt.";
  if (reason instanceof HTTPProblem) return reason.message;
  return "Die Antwort war nicht vertragskonform oder die Verbindung ist unterbrochen.";
}

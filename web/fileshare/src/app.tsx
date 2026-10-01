import { useCallback, useEffect, useMemo, useRef, useState } from "preact/hooks";
import { asRecord, fetchJSON, HTTPProblem } from "../../shared/http";
import { formatBytes, formatTime } from "../../shared/format";
import { type FilesPage, type Session, type SharedFile } from "./model";

export type LoadedFileshare =
  | { state: "unavailable"; apiMode: "shadow" }
  | { state: "ready"; session: Session; page: FilesPage; apiMode: "shadow" | "active" };
export type FileshareLoader = (signal?: AbortSignal) => Promise<LoadedFileshare>;

export async function loadFileshare(signal?: AbortSignal): Promise<LoadedFileshare> {
  const result = await fetchJSON("/api/v1/fileshare/status", signal);
  const status = asRecord(result.value);
  if (result.mode !== "shadow" || status.state !== "unavailable" || status.reason !== "shadow_mode") {
    throw new Error("Unbekannter Fileshare-Status.");
  }
  return { state: "unavailable", apiMode: "shadow" };
}

interface AppProps {
  loader?: FileshareLoader;
}

export function App({ loader = loadFileshare }: AppProps) {
  const [data, setData] = useState<LoadedFileshare | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState("");
  const request = useRef<AbortController | null>(null);

  const refresh = useCallback(
    async () => {
      request.current?.abort();
      const controller = new AbortController();
      request.current = controller;
      setRefreshing(true);
      setData(null);
      setError(null);
      try {
        const result = await loader(controller.signal);
        if (!controller.signal.aborted) setData(result);
      } catch (reason) {
        if (!controller.signal.aborted) setError(friendlyError(reason));
      } finally {
        if (!controller.signal.aborted) setRefreshing(false);
      }
    },
    [loader],
  );

  useEffect(() => {
    void refresh();
    return () => request.current?.abort();
  }, [refresh]);

  const files = data?.state === "ready" ? data : null;
  const visibleFiles = useMemo(() => {
    const needle = filter.trim().toLocaleLowerCase("de-DE");
    return (
      files?.page.items.filter((file) => needle === "" || file.filename.toLocaleLowerCase("de-DE").includes(needle)) ??
      []
    );
  }, [files, filter]);

  return (
    <div class="app-shell">
      <a class="skip-link" href="#main">
        Zum Inhalt
      </a>
      <header class="topbar">
        <div class="brand">
          <strong>Plntir</strong>
          <span>Fileshare</span>
        </div>
        <span class="status status-warning">
          {data?.state === "unavailable" ? "Nicht verfügbar" : files ? "Nur lesen" : "Status unbekannt"}
        </span>
      </header>
      <main class="page files-page" id="main">
        <div class="page-heading">
          <div>
            <h1>Meine Dateien</h1>
            <p class="lede">Verschlüsselte Dateien auf deinen registrierten Geräten – ohne öffentliches Verzeichnis.</p>
          </div>
        </div>

        {data?.state === "unavailable" && (
          <div class="notice" role="status">
            <p>
              <strong>Fileshare ist noch nicht verfügbar.</strong> Die Dateiliste und Dateiübertragung sind noch
              nicht angebunden.
            </p>
          </div>
        )}
        {error && (
          <div class="error-panel" role="alert">
            <p>
              <strong>Fileshare konnte nicht geladen werden.</strong> {error}
            </p>
          </div>
        )}

        <section class="section" aria-labelledby="files-title">
          <div class="section-heading">
            <div>
              <h2 id="files-title">Dateiliste</h2>
              {files && <span class="meta">Sitzung bis {formatTime(files.session.idleExpiresAt)}</span>}
            </div>
            <button type="button" disabled={refreshing} onClick={() => void refresh()}>
              {refreshing ? "Lädt …" : "Aktualisieren"}
            </button>
          </div>
          {!files ? (
            refreshing ? (
              <Loading />
            ) : (
              <Empty
                title="Keine Dateiliste verfügbar"
                detail={
                  data?.state === "unavailable"
                    ? "Der Dienst bietet noch keinen Dateizugriff an."
                    : "Der Dateizugriff konnte nicht geprüft werden."
                }
              />
            )
          ) : (
            <>
              <div class="toolbar file-toolbar">
                <div class="field">
                  <label for="file-filter">Dateien filtern</label>
                  <input
                    id="file-filter"
                    type="search"
                    value={filter}
                    onInput={(event) => setFilter(event.currentTarget.value)}
                    autoComplete="off"
                  />
                </div>
                <span class="meta">
                  {visibleFiles.length} von {files.page.items.length}
                </span>
              </div>
              {visibleFiles.length === 0 ? (
                <Empty
                  title={files.page.items.length === 0 ? "Noch keine Dateien" : "Keine Treffer"}
                  detail={
                    files.page.items.length === 0
                      ? "Nach Freigabe des aktiven Modus erscheinen eigene und empfangene Dateien hier."
                      : "Ändere den Filter, um andere Dateien zu sehen."
                  }
                />
              ) : (
                <FileList files={visibleFiles} accountId={files.session.accountId} />
              )}
              {files.page.nextCursor && (
                <p class="notice-inline">
                  Weitere Ergebnisse sind vorhanden. Pagination wird vor dem aktiven Cutover angeschlossen.
                </p>
              )}
            </>
          )}
        </section>
      </main>
    </div>
  );
}

function FileList({ files, accountId }: { files: SharedFile[]; accountId: string }) {
  return (
    <ul class="file-list">
      {files.map((file) => {
        return (
          <li key={file.id} class="file-row">
            <div class="file-main">
              <strong>{file.filename}</strong>
              <span class="meta">
                {file.ownerAccountId === accountId ? "Eigene Datei" : "Mit mir geteilt"} ·{" "}
                {formatBytes(file.logicalSizeBytes)}
              </span>
              <span class="identifier meta">{file.id}</span>
            </div>
            <div>
              <span class={`status ${scanClass(file.scanState)}`}>{scanLabel(file.scanState)}</span>
              <br />
              <span class="meta">{stateLabel(file.state)}</span>
            </div>
            <button
              type="button"
              disabled
              title="Downloads sind noch nicht angebunden"
            >
              Herunterladen
            </button>
          </li>
        );
      })}
    </ul>
  );
}

function Loading() {
  return (
    <div class="loading-lines" aria-live="polite" aria-busy="true">
      <div class="loading-line" />
      <div class="loading-line" />
    </div>
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

function scanClass(state: SharedFile["scanState"]): string {
  if (state === "clean") return "status-ok";
  if (["malware", "unscannable", "failed"].includes(state)) return "status-danger";
  return "status-warning";
}

function scanLabel(state: SharedFile["scanState"]): string {
  return {
    pending_upload: "Upload ausstehend",
    queued: "Scan wartet",
    scanning: "Wird geprüft",
    clean: "Sauber",
    malware: "Malware",
    unscannable: "Nicht prüfbar",
    failed: "Scan fehlgeschlagen",
  }[state];
}

function stateLabel(state: SharedFile["state"]): string {
  return {
    uploading: "Wird hochgeladen",
    active: "Aktiv",
    trashed: "Papierkorb",
    deletion_pending: "Löschung ausstehend",
    purged: "Kryptografisch gelöscht",
  }[state];
}

function friendlyError(reason: unknown): string {
  if (reason instanceof HTTPProblem && reason.status === 401)
    return "Die Cloudflare-Access-Anmeldung fehlt oder ist ungültig.";
  if (reason instanceof HTTPProblem) return reason.message;
  return "Die Antwort war nicht vertragskonform oder die Verbindung ist unterbrochen.";
}

import { useCallback, useEffect, useMemo, useState } from "preact/hooks";
import { fetchJSON, HTTPProblem } from "../../shared/http";
import { formatBytes, formatTime } from "../../shared/format";
import { type FilesPage, type Session, type SharedFile, parseFiles, parseSession } from "./model";

export interface LoadedFileshare {
  session: Session;
  page: FilesPage;
  apiMode: string;
}
export type FileshareLoader = (signal?: AbortSignal) => Promise<LoadedFileshare>;

export async function loadFileshare(signal?: AbortSignal): Promise<LoadedFileshare> {
  const [sessionResult, filesResult] = await Promise.all([
    fetchJSON("/api/v1/session", signal),
    fetchJSON("/api/v1/files", signal),
  ]);
  return {
    session: parseSession(sessionResult.value),
    page: parseFiles(filesResult.value),
    apiMode: sessionResult.mode === filesResult.mode ? sessionResult.mode : "unknown",
  };
}

interface AppProps {
  loader?: FileshareLoader;
}

export function App({ loader = loadFileshare }: AppProps) {
  const [data, setData] = useState<LoadedFileshare | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [filter, setFilter] = useState("");
  const [selectionNote, setSelectionNote] = useState<string | null>(null);

  const refresh = useCallback(
    async (signal?: AbortSignal) => {
      setRefreshing(true);
      setError(null);
      try {
        setData(await loader(signal));
      } catch (reason) {
        if (!signal?.aborted) setError(friendlyError(reason));
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

  const active = data?.apiMode === "active";
  const visibleFiles = useMemo(() => {
    const needle = filter.trim().toLocaleLowerCase("de-DE");
    return (
      data?.page.items.filter((file) => needle === "" || file.filename.toLocaleLowerCase("de-DE").includes(needle)) ??
      []
    );
  }, [data, filter]);

  const chooseFile = (event: Event) => {
    const input = event.currentTarget as HTMLInputElement;
    const file = input.files?.item(0);
    input.value = "";
    if (!file) return;
    if (file.size > 500_000_000_000) setSelectionNote("Diese Datei überschreitet das absolute Limit von 500 GB.");
    else if (file.size > 5_000_000_000)
      setSelectionNote(
        "Dateien über 5 GB werden in v1 ausschließlich mit dem macOS-Transfer-Agenten verschlüsselt übertragen.",
      );
    else
      setSelectionNote(
        `${file.name} (${formatBytes(file.size)}) wurde ausgewählt. Der Browser-Upload ist noch nicht freigegeben.`,
      );
  };

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
        <span class={`status ${active ? "status-ok" : "status-warning"}`}>
          {active ? "Aktiv" : "Shadow · nur lesen"}
        </span>
      </header>
      <main class="page files-page" id="main">
        <div class="page-heading">
          <div>
            <h1>Meine Dateien</h1>
            <p class="lede">Verschlüsselte Dateien auf deinen registrierten Geräten – ohne öffentliches Verzeichnis.</p>
          </div>
          <label class={`file-action primary-action ${!active ? "file-action-disabled" : ""}`}>
            Datei auswählen
            <input type="file" disabled={!active} onChange={chooseFile} aria-describedby="upload-help" />
          </label>
        </div>

        {!active && (
          <div class="notice" role="status">
            <p>
              <strong>Fileshare ist noch nicht aktiv.</strong> Session, Upload und Download bleiben im Shadow-Aufbau
              gesperrt. Der laufende Dienst wird nicht verändert.
            </p>
          </div>
        )}
        <p class="field-help" id="upload-help">
          Im Browser höchstens 5 GB. Größere Bilder und Videos bis 500 GB laufen ausschließlich über den
          macOS-Transfer-Agenten; Hotspots werden abgelehnt.
        </p>
        {selectionNote && (
          <div class="notice" role="status">
            <p>{selectionNote}</p>
          </div>
        )}
        {error && (
          <div class="error-panel" role="alert">
            <p>
              <strong>Fileshare konnte nicht geladen werden.</strong> {error}
            </p>
            {data && <p>Die zuletzt geladene Liste bleibt sichtbar.</p>}
          </div>
        )}

        <section class="section" aria-labelledby="files-title">
          <div class="section-heading">
            <div>
              <h2 id="files-title">Dateiliste</h2>
              {data && <span class="meta">Sitzung bis {formatTime(data.session.idleExpiresAt)}</span>}
            </div>
            <button type="button" disabled={refreshing} onClick={() => void refresh()}>
              {refreshing ? "Lädt …" : "Aktualisieren"}
            </button>
          </div>
          {!data ? (
            refreshing ? (
              <Loading />
            ) : (
              <Empty title="Noch keine Dateiliste" detail="Die geschützte Fileshare-API ist noch nicht erreichbar." />
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
                  {visibleFiles.length} von {data.page.items.length}
                </span>
              </div>
              {visibleFiles.length === 0 ? (
                <Empty
                  title={data.page.items.length === 0 ? "Noch keine Dateien" : "Keine Treffer"}
                  detail={
                    data.page.items.length === 0
                      ? "Nach Freigabe des aktiven Modus erscheinen eigene und empfangene Dateien hier."
                      : "Ändere den Filter, um andere Dateien zu sehen."
                  }
                />
              ) : (
                <FileList files={visibleFiles} accountId={data.session.accountId} active={active} />
              )}
              {data.page.nextCursor && (
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

function FileList({ files, accountId, active }: { files: SharedFile[]; accountId: string; active: boolean }) {
  return (
    <ul class="file-list">
      {files.map((file) => {
        const downloadable = active && file.state === "active" && file.scanState === "clean";
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
              disabled={!downloadable}
              title={downloadable ? "Download-Ticket anfordern" : downloadReason(file, active)}
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

function downloadReason(file: SharedFile, active: boolean): string {
  if (!active) return "Im Shadow-Modus gesperrt";
  if (file.state !== "active") return "Datei ist nicht aktiv";
  if (file.scanState !== "clean") return "Download bleibt bis zu einem sauberen Scan gesperrt";
  return "Download gesperrt";
}

function friendlyError(reason: unknown): string {
  if (reason instanceof HTTPProblem && reason.status === 404)
    return "Die Session- und Dateirouten sind im Shadow-Modus absichtlich noch nicht verfügbar.";
  if (reason instanceof HTTPProblem && reason.status === 401)
    return "Cloudflare-Access-Anmeldung oder registriertes WARP-Gerät fehlt.";
  if (reason instanceof HTTPProblem) return reason.message;
  return "Die Antwort war nicht vertragskonform oder die Verbindung ist unterbrochen.";
}

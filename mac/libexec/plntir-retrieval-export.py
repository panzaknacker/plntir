import base64
import datetime
import grp
import hashlib
import itertools
import json
import mimetypes
import os
import pathlib
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse

BASE = pathlib.Path("/Users/plntir-operator").resolve(strict=True)
EXPORT_DIR = pathlib.Path("/Users/Shared/.plntir/archive/retrievals")
EXPORT_GROUP = "plntirarchive"
MAX_BYTES = 50 * 1024 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_DIRECTORY_ENTRIES = 2000
MAX_PREVIEW_BYTES = 512 * 1024
MAX_SAFARI_ROWS = 5000
ARCHIVE_NAME = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9._-]{1,80}-[a-f0-9]{16}[.]tar[.]gz$")


def fail(message, code=1):
    print(json.dumps({"ok": False, "error": message}, separators=(",", ":")))
    raise SystemExit(code)


def decode_path(token):
    try:
        raw = base64.b64decode(token, validate=True)
        if len(raw) > MAX_PATH_BYTES:
            fail("path too long", 64)
        path = raw.decode("utf-8")
    except Exception:
        fail("invalid base64 path", 64)
    if not path.startswith("/") or chr(0) in path:
        fail("absolute path required", 64)
    try:
        resolved = pathlib.Path(path).resolve(strict=True)
    except OSError as exc:
        fail("path unavailable: " + str(exc), 66)
    try:
        common = pathlib.Path(os.path.commonpath((str(BASE), str(resolved))))
    except ValueError:
        fail("path outside managed home", 77)
    if common != BASE:
        fail("path outside managed home", 77)
    return resolved


def scan(path):
    files = 0
    directories = 0
    bytes_total = 0
    unreadable = 0

    def onerror(_error):
        nonlocal unreadable
        unreadable += 1

    try:
        stat_result = path.lstat()
    except OSError:
        return 0, 0, 0, 1
    if path.is_file():
        return 1, 0, stat_result.st_size, 0
    if path.is_symlink():
        return 1, 0, 0, 0

    for root, dirs, names in os.walk(path, followlinks=False, onerror=onerror):
        directories += 1
        if not os.access(root, os.R_OK | os.X_OK):
            unreadable += 1
        for name in names:
            candidate = pathlib.Path(root) / name
            try:
                item = candidate.lstat()
                files += 1
                if candidate.is_file():
                    bytes_total += item.st_size
                    if not os.access(candidate, os.R_OK):
                        unreadable += 1
            except OSError:
                unreadable += 1
        dirs[:] = [name for name in dirs if not (pathlib.Path(root) / name).is_symlink()]
        if bytes_total > MAX_BYTES:
            break
    return files, directories, bytes_total, unreadable


def iso_time(timestamp):
    return datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def list_directory(path):
    if not path.is_dir():
        fail("path is not a directory", 66)

    entries = []
    unreadable = 0
    truncated = False
    try:
        children = list(itertools.islice(path.iterdir(), MAX_DIRECTORY_ENTRIES + 1))
    except OSError as exc:
        fail("directory unavailable: " + str(exc), 74)

    if len(children) > MAX_DIRECTORY_ENTRIES:
        children = children[:MAX_DIRECTORY_ENTRIES]
        truncated = True

    for candidate in children:
        try:
            item = candidate.lstat()
            if stat.S_ISLNK(item.st_mode):
                item_type = "symlink"
                item_bytes = 0
            elif stat.S_ISDIR(item.st_mode):
                item_type = "directory"
                item_bytes = 0
            elif stat.S_ISREG(item.st_mode):
                item_type = "file"
                item_bytes = item.st_size
            else:
                item_type = "other"
                item_bytes = item.st_size
            readable = os.access(candidate, os.R_OK)
            if item_type == "directory":
                readable = readable and os.access(candidate, os.X_OK)
            if not readable:
                unreadable += 1
            entries.append(
                {
                    "name": candidate.name,
                    "path": str(candidate),
                    "type": item_type,
                    "bytes": item_bytes,
                    "modified_at": iso_time(item.st_mtime),
                    "mode": format(stat.S_IMODE(item.st_mode), "04o"),
                    "hidden": candidate.name.startswith("."),
                    "readable": readable,
                }
            )
        except OSError:
            unreadable += 1
            entries.append(
                {
                    "name": candidate.name,
                    "path": str(candidate),
                    "type": "unavailable",
                    "bytes": 0,
                    "modified_at": "",
                    "mode": "",
                    "hidden": candidate.name.startswith("."),
                    "readable": False,
                }
            )
    entries.sort(key=lambda entry: (entry["type"] != "directory", entry["name"].casefold()))

    parent = ""
    if path != BASE:
        parent = str(path.parent)
    result = {
        "schema_version": 1,
        "ok": unreadable == 0,
        "path": str(path),
        "parent": parent,
        "entries": entries,
        "entry_count": len(entries),
        "unreadable": unreadable,
        "truncated": truncated,
    }
    log_event(
        "list path=%s entries=%d unreadable=%d truncated=%s" % (path, len(entries), unreadable, str(truncated).lower())
    )
    print(json.dumps(result, separators=(",", ":")))
    raise SystemExit(0)


def preview_file(path):
    try:
        item = path.lstat()
    except OSError as exc:
        fail("file unavailable: " + str(exc), 66)
    if stat.S_ISLNK(item.st_mode) or not stat.S_ISREG(item.st_mode):
        fail("preview requires a regular non-symlink file", 66)
    try:
        with path.open("rb") as stream:
            contents = stream.read(MAX_PREVIEW_BYTES + 1)
    except OSError as exc:
        fail("file preview failed: " + str(exc), 74)

    truncated = len(contents) > MAX_PREVIEW_BYTES
    contents = contents[:MAX_PREVIEW_BYTES]
    text = ""
    kind = "binary"
    if b"\x00" not in contents:
        try:
            text = contents.decode("utf-8")
            kind = "text"
        except UnicodeDecodeError:
            pass
    mime_type = mimetypes.guess_type(path.name)[0] or ("text/plain" if kind == "text" else "application/octet-stream")
    result = {
        "schema_version": 1,
        "ok": True,
        "path": str(path),
        "bytes": item.st_size,
        "returned_bytes": len(contents),
        "truncated": truncated,
        "kind": kind,
        "mime": mime_type[:255],
        "text": text if kind == "text" else "",
        "hex_preview": contents[:256].hex() if kind == "binary" else "",
    }
    log_event(
        "preview path=%s bytes=%d returned=%d kind=%s truncated=%s"
        % (path, item.st_size, len(contents), kind, str(truncated).lower())
    )
    print(json.dumps(result, separators=(",", ":")))
    raise SystemExit(0)


def safari_columns(connection, table):
    return {row[1] for row in connection.execute("PRAGMA table_info(%s)" % table)}


def safari_history(hours, limit):
    requested_history_path = BASE / "Library" / "Safari" / "History.db"
    if (
        not requested_history_path.exists()
        or requested_history_path.is_symlink()
        or not requested_history_path.is_file()
    ):
        fail("Safari History.db is unavailable", 66)
    try:
        history_path = requested_history_path.resolve(strict=True)
        common = pathlib.Path(os.path.commonpath((str(BASE), str(history_path))))
    except (OSError, ValueError) as exc:
        fail("Safari History.db is unavailable: " + str(exc), 66)
    if common != BASE:
        fail("Safari History.db is outside managed home", 77)

    temp_dir = tempfile.mkdtemp(prefix="plntir-safari.", dir="/private/var/tmp")
    os.chmod(temp_dir, 0o700)
    snapshot_path = pathlib.Path(temp_dir) / "History.snapshot.db"
    source = None
    snapshot = None
    try:
        quoted = urllib.parse.quote(str(history_path), safe="/")
        source = sqlite3.connect(
            "file:%s?mode=ro" % quoted,
            uri=True,
            timeout=3,
        )
        snapshot = sqlite3.connect(str(snapshot_path))
        source.backup(snapshot, pages=1024)
        snapshot.commit()

        tables = {row[0] for row in snapshot.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"history_items", "history_visits"}.issubset(tables):
            fail("unsupported Safari history schema", 65)
        item_columns = safari_columns(snapshot, "history_items")
        visit_columns = safari_columns(snapshot, "history_visits")
        required_items = {"id", "url"}
        required_visits = {"history_item", "visit_time"}
        if not required_items.issubset(item_columns) or not required_visits.issubset(visit_columns):
            fail("unsupported Safari history columns", 65)

        if "title" in visit_columns:
            title_expression = "v.title"
        elif "title" in item_columns:
            title_expression = "i.title"
        else:
            title_expression = "''"
        successful_expression = "v.load_successful" if "load_successful" in visit_columns else "NULL"
        non_get_expression = "v.http_non_get" if "http_non_get" in visit_columns else "NULL"
        cutoff = time.time() - 978307200 - (hours * 3600)
        query = """
            SELECT v.visit_time, i.url, %s, %s, %s
            FROM history_visits AS v
            JOIN history_items AS i ON i.id = v.history_item
            WHERE v.visit_time >= ?
            ORDER BY v.visit_time DESC
            LIMIT ?
        """ % (title_expression, successful_expression, non_get_expression)

        rows = []
        for visit_time, url, title, load_successful, http_non_get in snapshot.execute(query, (cutoff, limit)):
            url = str(url or "")[:32768]
            title = str(title or "")[:8192]
            try:
                domain = urllib.parse.urlsplit(url).hostname or ""
            except ValueError:
                domain = ""
            rows.append(
                {
                    "visited_at": iso_time(float(visit_time) + 978307200),
                    "domain": domain,
                    "url": url,
                    "title": title,
                    "load_successful": None if load_successful is None else bool(load_successful),
                    "http_non_get": None if http_non_get is None else bool(http_non_get),
                }
            )

        result = {
            "schema_version": 1,
            "ok": True,
            "source": str(history_path),
            "hours": hours,
            "limit": limit,
            "returned": len(rows),
            "truncated": len(rows) == limit,
            "captured_at": iso_time(time.time()),
            "visits": rows,
        }
        log_event("safari-history hours=%d returned=%d limit=%d" % (hours, len(rows), limit))
        print(json.dumps(result, separators=(",", ":")))
        raise SystemExit(0)
    except sqlite3.Error as exc:
        fail("Safari history snapshot failed: " + str(exc), 74)
    finally:
        if source is not None:
            source.close()
        if snapshot is not None:
            snapshot.close()
        shutil.rmtree(temp_dir, ignore_errors=True)


def log_event(message):
    subprocess.run(
        ["/usr/bin/logger", "-t", "plntir-retrieval-export", "--", message],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def prune():
    cutoff = time.time() - 86400
    for entry in EXPORT_DIR.iterdir():
        try:
            if (
                not entry.is_symlink()
                and ARCHIVE_NAME.fullmatch(entry.name)
                and entry.is_file()
                and entry.stat().st_mtime < cutoff
            ):
                entry.unlink()
        except OSError:
            pass


if len(sys.argv) == 4 and sys.argv[1] == "safari-history":
    try:
        requested_hours = int(sys.argv[2])
        requested_limit = int(sys.argv[3])
    except ValueError:
        fail("Safari history hours and limit must be integers", 64)
    if requested_hours < 1 or requested_hours > 8760:
        fail("Safari history hours must be between 1 and 8760", 64)
    if requested_limit < 1 or requested_limit > MAX_SAFARI_ROWS:
        fail("Safari history limit must be between 1 and 5000", 64)
    safari_history(requested_hours, requested_limit)

if len(sys.argv) != 3 or sys.argv[1] not in {"list-b64", "preview-b64", "probe-b64", "export-b64"}:
    fail(
        "usage: plntir-retrieval-export list-b64|preview-b64|probe-b64|export-b64 BASE64_PATH | safari-history HOURS LIMIT",
        64,
    )

mode = sys.argv[1]
requested = decode_path(sys.argv[2])
if mode == "list-b64":
    list_directory(requested)
if mode == "preview-b64":
    preview_file(requested)
files, directories, bytes_total, unreadable = scan(requested)

if bytes_total > MAX_BYTES:
    fail("selection exceeds 50 GiB limit", 75)

if mode == "probe-b64":
    result = {
        "ok": unreadable == 0,
        "path": str(requested),
        "files": files,
        "directories": directories,
        "bytes": bytes_total,
        "unreadable": unreadable,
    }
    log_event("probe path=%s files=%d bytes=%d unreadable=%d" % (requested, files, bytes_total, unreadable))
    print(json.dumps(result, separators=(",", ":")))
    raise SystemExit(0 if unreadable == 0 else 74)

EXPORT_DIR.mkdir(mode=0o2770, parents=True, exist_ok=True)
prune()
free_bytes = shutil.disk_usage(EXPORT_DIR).free
if free_bytes < bytes_total + (1024 * 1024 * 1024):
    fail("insufficient free space for export", 75)

stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", requested.name or "home")[:80]
archive = EXPORT_DIR / ("%s-%s-%s.tar.gz" % (stamp, safe_name, secrets.token_hex(8)))
relative_target = requested.relative_to(BASE)
if str(relative_target) == ".":
    cwd = BASE.parent
    target = BASE.name
else:
    cwd = BASE
    target = str(relative_target)

completed = subprocess.run(
    ["/usr/bin/tar", "-czf", str(archive), "-C", str(cwd), "--", target],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.PIPE,
    text=True,
)
if completed.returncode != 0:
    try:
        archive.unlink()
    except OSError:
        pass
    fail("archive failed: " + completed.stderr[-500:], 74)

os.chmod(archive, 0o640)
os.chown(archive, os.getuid(), grp.getgrnam(EXPORT_GROUP).gr_gid)
digest = hashlib.sha256()
with archive.open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)

result = {
    "ok": True,
    "source": str(requested),
    "archive": str(archive),
    "sha256": digest.hexdigest(),
    "archive_bytes": archive.stat().st_size,
    "source_bytes": bytes_total,
    "files": files,
    "directories": directories,
    "unreadable": unreadable,
}
log_event(
    "export source=%s archive=%s sha256=%s bytes=%d unreadable=%d"
    % (requested, archive, result["sha256"], result["archive_bytes"], unreadable)
)
print(json.dumps(result, separators=(",", ":")))

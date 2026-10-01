#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import pathlib
import sqlite3
import subprocess
import sys
import tempfile
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "mac/libexec/plntir-retrieval-export.py.in"


def token(path):
    return base64.b64encode(os.fsencode(path)).decode("ascii")


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def invoke(script, *arguments, expected=0):
    completed = subprocess.run(
        [sys.executable, str(script), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if completed.returncode != expected:
        raise AssertionError(
            f"command {arguments!r} returned {completed.returncode}: {completed.stdout} {completed.stderr}"
        )
    return json.loads(completed.stdout)


def main():
    with tempfile.TemporaryDirectory(prefix="plntir-web-test.") as temporary:
        root = pathlib.Path(temporary)
        home = root / "Managed User"
        private_tmp = root / "private-tmp"
        documents = home / "Documents"
        safari = home / "Library" / "Safari"
        documents.mkdir(parents=True)
        safari.mkdir(parents=True)
        private_tmp.mkdir()
        (documents / "report.txt").write_text("report\n", encoding="utf-8")
        (home / ".private-note").write_text("hidden\n", encoding="utf-8")
        outside = root / "outside.txt"
        outside.write_text("outside\n", encoding="utf-8")
        (home / "outside-link").symlink_to(outside)

        generated = TEMPLATE.read_text(encoding="utf-8")
        generated = generated.replace("@MANAGED_HOME@", str(home))
        generated = generated.replace(
            'dir="/private/var/tmp"',
            f"dir={str(private_tmp)!r}",
        )
        generated = generated.replace(
            '["/usr/bin/logger",',
            '["/usr/bin/true",',
        )
        script = root / "retrieval-export.py"
        script.write_text(generated, encoding="utf-8")

        listing = invoke(script, "list-b64", token(home))
        assert listing["schema_version"] == 1
        assert listing["path"] == str(home.resolve())
        assert listing["parent"] == ""
        entries = {entry["name"]: entry for entry in listing["entries"]}
        assert entries["Documents"]["type"] == "directory"
        assert entries[".private-note"]["hidden"] is True
        assert entries["outside-link"]["type"] == "symlink"
        assert "report.txt" not in entries

        preview = invoke(script, "preview-b64", token(documents / "report.txt"))
        assert preview["kind"] == "text"
        assert preview["text"] == "report\n"
        assert preview["returned_bytes"] == 7
        binary = documents / "binary.dat"
        binary.write_bytes(b"A\x00B")
        binary_preview = invoke(script, "preview-b64", token(binary))
        assert binary_preview["kind"] == "binary"
        assert binary_preview["hex_preview"] == "410042"
        large_text = documents / "large.txt"
        large_text.write_bytes(b"x" * ((512 * 1024) + 1))
        large_preview = invoke(script, "preview-b64", token(large_text))
        assert large_preview["kind"] == "text"
        assert large_preview["returned_bytes"] == 512 * 1024
        assert large_preview["truncated"] is True

        large_directory = home / "LargeDirectory"
        large_directory.mkdir()
        for index in range(2002):
            (large_directory / f"entry-{index:04d}").touch()
        large_listing = invoke(script, "list-b64", token(large_directory))
        assert large_listing["entry_count"] == 2000
        assert large_listing["truncated"] is True

        rejected = invoke(script, "list-b64", token(home / "outside-link"), expected=77)
        assert rejected["ok"] is False
        assert "outside managed home" in rejected["error"]

        history = safari / "History.db"
        connection = sqlite3.connect(history)
        connection.executescript(
            """
            CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT NOT NULL);
            CREATE TABLE history_visits (
                id INTEGER PRIMARY KEY,
                history_item INTEGER NOT NULL,
                visit_time REAL NOT NULL,
                title TEXT,
                load_successful INTEGER,
                http_non_get INTEGER
            );
            """
        )
        apple_now = time.time() - 978307200
        connection.executemany(
            "INSERT INTO history_items(id, url) VALUES (?, ?)",
            [
                (1, "https://example.com/recent?q=1"),
                (2, "https://old.example/old"),
            ],
        )
        connection.executemany(
            "INSERT INTO history_visits(history_item, visit_time, title, load_successful, http_non_get) VALUES (?, ?, ?, ?, ?)",
            [
                (1, apple_now - 60, "Recent visit", 1, 0),
                (2, apple_now - (48 * 3600), "Old visit", 1, 0),
            ],
        )
        connection.commit()
        connection.close()
        before = digest(history)

        result = invoke(script, "safari-history", "24", "100")
        assert result["schema_version"] == 1
        assert result["returned"] == 1
        assert result["visits"][0]["domain"] == "example.com"
        assert result["visits"][0]["title"] == "Recent visit"
        assert result["visits"][0]["url"] == "https://example.com/recent?q=1"
        assert digest(history) == before
        assert list(private_tmp.iterdir()) == []

        real_safari = home / "Library" / "Safari.real"
        safari.rename(real_safari)
        outside_safari = root / "outside-safari"
        outside_safari.mkdir()
        (outside_safari / "History.db").write_bytes((real_safari / "History.db").read_bytes())
        safari.symlink_to(outside_safari, target_is_directory=True)
        escaped = invoke(script, "safari-history", "24", "100", expected=77)
        assert escaped["ok"] is False
        assert "outside managed home" in escaped["error"]

    print("Web dashboard Mac data checks passed.")


if __name__ == "__main__":
    main()

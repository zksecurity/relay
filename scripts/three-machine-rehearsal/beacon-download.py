#!/usr/bin/env python3
"""Resumable public retrieval only; proof-tool still authenticates each beacon."""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

CHAIN = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
OPERATORS = (("protocol-labs", "https://api.drand.sh"),
             ("cloudflare", "https://drand.cloudflare.com"))


def read_regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 131072:
            raise ValueError(f"not a bounded regular file: {path}")
        return stream.read(131073)


def retain(path, data):
    """Atomic create-only publication; interrupted temporary files are ignored."""
    if os.path.lexists(path):
        if read_regular(path) != data:
            raise ValueError(f"existing output differs; preserve and investigate: {path}")
        return
    fd, name = tempfile.mkstemp(prefix=".download-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(name, path)  # Never replace an existing file.
    finally:
        os.unlink(name)


def check_raw(raw, round_number):
    value = json.loads(raw)
    if type(value.get("round")) is not int or value["round"] != round_number:
        raise ValueError("beacon response has the wrong committed round")
    if not re.fullmatch(r"[0-9a-f]{64}", value.get("randomness", "")):
        raise ValueError("beacon response has invalid randomness")
    if not re.fullmatch(r"[0-9a-f]{96}", value.get("signature", "")):
        raise ValueError("beacon response has invalid Quicknet signature shape")
    return value["randomness"], value["signature"]


def fetch(url):
    result = subprocess.run([
        "curl", "--fail", "--silent", "--show-error", "--proto", "=https",
        "--connect-timeout", "10", "--max-time", "25", "--retry", "2",
        "--retry-delay", "2", "--retry-max-time", "80", "--max-filesize", "65536",
        url], check=True, stdout=subprocess.PIPE)
    return result.stdout.decode("utf-8")


def collect(directory, round_number, retrieve=fetch):
    directory = Path(directory)
    if os.path.realpath(directory) != os.path.abspath(directory):
        raise ValueError("relay directory must not contain symlink components")
    directory.mkdir(mode=0o700, exist_ok=True)
    lockfd = os.open(directory / ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lockfd, "w") as lock:
        if not stat.S_ISREG(os.fstat(lock.fileno()).st_mode):
            raise ValueError("download lock must be a regular file")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        rows = ["relay_id\toperator_id\tendpoint_sha256\tretrieved_at\tfilename"]
        answers = []
        first_time = None
        for operator, base in OPERATORS:
            url = f"{base}/{CHAIN}/public/{round_number}"
            checkpoint = directory / f"{operator}.retrieval.json"
            if os.path.lexists(checkpoint):
                saved = json.loads(read_regular(checkpoint))
                if saved["url"] != url or saved["operator"] != operator:
                    raise ValueError("saved retrieval belongs to another round or operator")
                datetime.datetime.strptime(saved["retrieved_at"], "%Y-%m-%dT%H:%M:%SZ")
            else:
                raw = retrieve(url)
                check_raw(raw, round_number)
                saved = {"url": url, "operator": operator, "raw": raw,
                         "retrieved_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
                retain(checkpoint, json.dumps(saved, sort_keys=True).encode())
            answers.append(check_raw(saved["raw"], round_number))
            filename = f"{operator}.json"
            retain(directory / filename, saved["raw"].encode())
            digest = hashlib.sha256(url.encode()).hexdigest()
            rows.append(f"{operator}\t{operator}\tsha256:{digest}\t{saved['retrieved_at']}\t{filename}")
            if first_time is None:
                first_time = saved["retrieved_at"]
        if len(set(answers)) != 1:
            raise ValueError("relay responses disagree; preserve files and investigate")
        retain(directory / "relays.tsv", (rows[0] + "\n" + "\n".join(sorted(rows[1:])) + "\n").encode())
        return first_time


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3 or not sys.argv[2].isdigit() or int(sys.argv[2]) < 1:
            raise ValueError("usage: beacon-download.py DIRECTORY POSITIVE_ROUND")
        print(collect(sys.argv[1], int(sys.argv[2])))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        sys.exit(f"Beacon retrieval paused; retained files can be retried: {error}")

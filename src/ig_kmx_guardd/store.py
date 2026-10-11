"""Crash-consistent lifecycle, replay journal, receipts, and bounded evidence."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

from . import cbor
from .model import Binding, State, TRANSITIONS, canonical, sha256_bytes

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS sessions(
 key TEXT PRIMARY KEY, binding TEXT NOT NULL, state TEXT NOT NULL,
 desired_state TEXT NOT NULL, cgroup_identity TEXT NOT NULL, worker_pid INTEGER,
 last_error TEXT, updated_ns INTEGER NOT NULL, receipt_seq INTEGER NOT NULL DEFAULT 0,
 prior_receipt_hash TEXT NOT NULL DEFAULT '', state_version INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX IF NOT EXISTS active_cgroup_identity
 ON sessions(cgroup_identity) WHERE state != 'DEACTIVATED';
CREATE TABLE IF NOT EXISTS requests(
 peer_uid INTEGER NOT NULL, request_id TEXT NOT NULL, nonce TEXT NOT NULL,
 request_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'COMPLETED',
 response BLOB, error TEXT, created_ns INTEGER NOT NULL, updated_ns INTEGER NOT NULL,
 PRIMARY KEY(peer_uid,request_id), UNIQUE(peer_uid,nonce),
 CHECK(status IN ('RESERVED','IN_PROGRESS','COMPLETED','FAILED')));
CREATE TABLE IF NOT EXISTS evidence(
 id INTEGER PRIMARY KEY AUTOINCREMENT, session_key TEXT NOT NULL, seq INTEGER NOT NULL,
 payload BLOB NOT NULL, created_ns INTEGER NOT NULL, UNIQUE(session_key,seq));
CREATE TABLE IF NOT EXISTS evidence_gaps(
 session_key TEXT PRIMARY KEY, dropped_count INTEGER NOT NULL DEFAULT 0,
 first_dropped_seq INTEGER, last_dropped_seq INTEGER, updated_ns INTEGER NOT NULL);
"""


class Store:
    def __init__(self, path: str, max_evidence: int = 10000):
        if not 1 <= max_evidence <= 1_000_000:
            raise ValueError("max_evidence outside [1, 1000000]")
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.lock = threading.RLock()
        self.max_evidence = max_evidence
        self._migrate()

    def _migrate(self) -> None:
        """Create the current schema and upgrade the 0.1 journal in place."""
        with self.lock:
            self.db.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")
            exists = self.db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='requests'"
            ).fetchone()
            if exists:
                columns = {row[1] for row in self.db.execute("PRAGMA table_info(requests)")}
                if "status" not in columns:
                    self.db.execute("ALTER TABLE requests ADD COLUMN status TEXT NOT NULL DEFAULT 'COMPLETED'")
                if "error" not in columns:
                    self.db.execute("ALTER TABLE requests ADD COLUMN error TEXT")
                if "updated_ns" not in columns:
                    self.db.execute("ALTER TABLE requests ADD COLUMN updated_ns INTEGER NOT NULL DEFAULT 0")
                    self.db.execute("UPDATE requests SET updated_ns=created_ns WHERE updated_ns=0")
            self.db.executescript(SCHEMA)
            session_columns = {row[1] for row in self.db.execute("PRAGMA table_info(sessions)")}
            if "state_version" not in session_columns:
                self.db.execute("ALTER TABLE sessions ADD COLUMN state_version INTEGER NOT NULL DEFAULT 0")

    def close(self) -> None:
        self.db.close()

    def recover(self) -> None:
        """Never reconstruct protection from stale disk state after process reboot."""
        now = time.time_ns()
        with self.lock, self.db:
            self.db.execute(
                "UPDATE sessions SET state=?,desired_state=?,updated_ns=? WHERE state NOT IN (?,?)",
                (State.RECONCILING, State.RECONCILING, now, State.DEACTIVATED, State.HELD),
            )
            self.db.execute(
                "UPDATE requests SET status='FAILED',error=?,updated_ns=? WHERE status IN ('RESERVED','IN_PROGRESS')",
                ("guardd restarted before durable completion", now),
            )

    def create(self, binding: Binding, cgroup_identity: dict) -> State:
        """Create a held session with exact, exclusive durable cgroup ownership."""
        encoded_binding = canonical(binding.dict()).decode()
        encoded_identity = canonical(cgroup_identity).decode()
        with self.lock, self.db:
            row = self.db.execute(
                "SELECT binding,state,cgroup_identity FROM sessions WHERE key=?", (binding.key(),)
            ).fetchone()
            if row:
                if row[0] != encoded_binding:
                    raise ValueError("session key rebound to different binding")
                if row[2] != encoded_identity:
                    raise ValueError("session key rebound to different cgroup identity")
                return State(row[1])
            owner = self.db.execute(
                "SELECT key,state FROM sessions WHERE cgroup_identity=? AND state!=?",
                (encoded_identity, State.DEACTIVATED),
            ).fetchone()
            if owner:
                raise ValueError(f"cgroup identity already owned by nonterminal session {owner[0]}")
            try:
                self.db.execute(
                    "INSERT INTO sessions(key,binding,state,desired_state,cgroup_identity,updated_ns) VALUES(?,?,?,?,?,?)",
                    (binding.key(), encoded_binding, State.HELD, State.HELD, encoded_identity, time.time_ns()),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("cgroup identity ownership collision") from exc
            return State.HELD

    def session(self, key: str) -> dict:
        row = self.db.execute(
            "SELECT binding,state,desired_state,cgroup_identity,worker_pid,last_error,updated_ns,receipt_seq,prior_receipt_hash,state_version "
            "FROM sessions WHERE key=?", (key,),
        ).fetchone()
        if not row:
            raise KeyError(key)
        names = [
            "binding", "state", "desired_state", "cgroup_identity", "worker_pid",
            "last_error", "updated_ns", "receipt_seq", "prior_receipt_hash", "state_version",
        ]
        output = dict(zip(names, row))
        output["binding"] = json.loads(output["binding"])
        output["cgroup_identity"] = json.loads(output["cgroup_identity"])
        return output

    def transition(self, key: str, target: State, error: str | None = None) -> State:
        with self.lock, self.db:
            current = State(self.session(key)["state"])
            if target == current:
                return current
            if target not in TRANSITIONS[current]:
                raise ValueError(f"non-monotonic transition {current}->{target}")
            self.db.execute(
                "UPDATE sessions SET state=?,desired_state=?,last_error=?,updated_ns=?,state_version=state_version+1 WHERE key=?",
                (target, target, error, time.time_ns(), key),
            )
            return target

    def require_state_version(self, key: str, expected: int) -> int:
        """Compare the caller's optimistic concurrency token with durable state."""
        actual = int(self.session(key)["state_version"])
        if expected != actual:
            raise ValueError(f"state version mismatch: expected {expected}, durable {actual}")
        return actual

    def set_worker(self, key: str, pid: int) -> None:
        with self.lock, self.db:
            self.db.execute(
                "UPDATE sessions SET worker_pid=?,updated_ns=? WHERE key=?", (pid, time.time_ns(), key),
            )

    def request_lookup(self, uid: int, request_id: str, request_hash: str) -> dict | None:
        row = self.db.execute(
            "SELECT request_hash,status,response,error FROM requests WHERE peer_uid=? AND request_id=?",
            (uid, request_id),
        ).fetchone()
        if not row:
            return None
        if row[0] != request_hash:
            raise ValueError("request_id collision")
        status, response, error = row[1:]
        if status == "COMPLETED":
            if response is None:
                raise RuntimeError("completed request has no durable response")
            return cbor.loads(bytes(response))
        if status == "FAILED":
            raise RuntimeError(f"prior request failed closed: {error or 'unspecified'}")
        raise RuntimeError(f"request already {status.lower()}")

    def nonce_used(self, uid: int, nonce: str) -> bool:
        return self.db.execute(
            "SELECT 1 FROM requests WHERE peer_uid=? AND nonce=?", (uid, nonce)
        ).fetchone() is not None

    def request_reserve(self, uid: int, request_id: str, nonce: str, request_hash: str) -> None:
        """Durably consume request ID and nonce before any operation side effect."""
        now = time.time_ns()
        with self.lock, self.db:
            try:
                self.db.execute(
                    "INSERT INTO requests(peer_uid,request_id,nonce,request_hash,status,response,error,created_ns,updated_ns) "
                    "VALUES(?,?,?,?, 'RESERVED',NULL,NULL,?,?)",
                    (uid, request_id, nonce, request_hash, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("request id or nonce already reserved") from exc

    def request_begin(self, uid: int, request_id: str, request_hash: str) -> None:
        with self.lock, self.db:
            changed = self.db.execute(
                "UPDATE requests SET status='IN_PROGRESS',updated_ns=? "
                "WHERE peer_uid=? AND request_id=? AND request_hash=? AND status='RESERVED'",
                (time.time_ns(), uid, request_id, request_hash),
            ).rowcount
            if changed != 1:
                raise RuntimeError("request reservation is not startable")

    def request_complete(self, uid: int, request_id: str, request_hash: str, response: dict) -> None:
        with self.lock, self.db:
            changed = self.db.execute(
                "UPDATE requests SET status='COMPLETED',response=?,error=NULL,updated_ns=? "
                "WHERE peer_uid=? AND request_id=? AND request_hash=? AND status='IN_PROGRESS'",
                (cbor.dumps(response), time.time_ns(), uid, request_id, request_hash),
            ).rowcount
            if changed != 1:
                raise RuntimeError("request completion was not persisted")

    def request_fail(self, uid: int, request_id: str, request_hash: str, error: str) -> None:
        with self.lock, self.db:
            self.db.execute(
                "UPDATE requests SET status='FAILED',error=?,updated_ns=? "
                "WHERE peer_uid=? AND request_id=? AND request_hash=? AND status!='FAILED'",
                (error[:1024], time.time_ns(), uid, request_id, request_hash),
            )

    def request_record(self, uid: int, request_id: str, nonce: str, request_hash: str, response: dict) -> None:
        """Compatibility wrapper retained for callers upgrading from 0.1.0."""
        self.request_reserve(uid, request_id, nonce, request_hash)
        self.request_begin(uid, request_id, request_hash)
        self.request_complete(uid, request_id, request_hash, response)

    def next_receipt(self, key: str) -> tuple[int, str]:
        with self.lock, self.db:
            session = self.session(key)
            sequence = session["receipt_seq"] + 1
            self.db.execute(
                "UPDATE sessions SET receipt_seq=?,updated_ns=? WHERE key=?",
                (sequence, time.time_ns(), key),
            )
            return sequence, session["prior_receipt_hash"]

    def chain_receipt(self, key: str, encoded: bytes) -> str:
        receipt_hash = sha256_bytes(encoded)
        with self.lock, self.db:
            self.db.execute(
                "UPDATE sessions SET prior_receipt_hash=?,updated_ns=? WHERE key=?",
                (receipt_hash, time.time_ns(), key),
            )
        return receipt_hash

    def add_evidence(self, key: str, payload: dict) -> int:
        """Append evidence with a per-session cap and durable loss accounting."""
        now = time.time_ns()
        with self.lock, self.db:
            sequence = self.db.execute(
                "SELECT COALESCE(MAX(seq),0)+1 FROM evidence WHERE session_key=?", (key,)
            ).fetchone()[0]
            self.db.execute(
                "INSERT INTO evidence(session_key,seq,payload,created_ns) VALUES(?,?,?,?)",
                (key, sequence, canonical(payload), now),
            )
            rows = self.db.execute(
                "SELECT id,seq FROM evidence WHERE session_key=? ORDER BY seq", (key,)
            ).fetchall()
            excess = len(rows) - self.max_evidence
            if excess > 0:
                removed = rows[:excess]
                self.db.executemany("DELETE FROM evidence WHERE id=?", ((row[0],) for row in removed))
                first_seq, last_seq = removed[0][1], removed[-1][1]
                self.db.execute(
                    "INSERT INTO evidence_gaps(session_key,dropped_count,first_dropped_seq,last_dropped_seq,updated_ns) "
                    "VALUES(?,?,?,?,?) ON CONFLICT(session_key) DO UPDATE SET "
                    "dropped_count=evidence_gaps.dropped_count+excluded.dropped_count,"
                    "first_dropped_seq=COALESCE(evidence_gaps.first_dropped_seq,excluded.first_dropped_seq),"
                    "last_dropped_seq=excluded.last_dropped_seq,updated_ns=excluded.updated_ns",
                    (key, excess, first_seq, last_seq, now),
                )
            return sequence

    def record_evidence_loss(self, key: str, count: int) -> None:
        """Durably account source/queue loss not represented by stored rows."""
        if count <= 0:
            return
        now = time.time_ns()
        with self.lock, self.db:
            self.db.execute(
                "INSERT INTO evidence_gaps(session_key,dropped_count,first_dropped_seq,last_dropped_seq,updated_ns) "
                "VALUES(?,?,?,?,?) ON CONFLICT(session_key) DO UPDATE SET "
                "dropped_count=evidence_gaps.dropped_count+excluded.dropped_count,"
                "updated_ns=excluded.updated_ns",
                (key, count, None, None, now),
            )

    def evidence_status(self, key: str) -> dict:
        retained, first_retained, last_retained = self.db.execute(
            "SELECT COUNT(*),MIN(seq),MAX(seq) FROM evidence WHERE session_key=?", (key,)
        ).fetchone()
        gap = self.db.execute(
            "SELECT dropped_count,first_dropped_seq,last_dropped_seq,updated_ns "
            "FROM evidence_gaps WHERE session_key=?", (key,),
        ).fetchone()
        return {
            "retained": retained,
            "first_retained_seq": first_retained,
            "last_retained_seq": last_retained,
            "dropped_count": gap[0] if gap else 0,
            "first_dropped_seq": gap[1] if gap else None,
            "last_dropped_seq": gap[2] if gap else None,
            "loss_updated_ns": gap[3] if gap else None,
            "degraded": bool(gap and gap[0]),
        }

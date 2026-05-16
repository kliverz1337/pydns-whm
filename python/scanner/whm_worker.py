"""WHM/cPanel scanner engine — standalone batch scanner with no DNS dependency.

Designed for WHM-first scanning: CIDR → TCP pre-check → HTTP probe → results.
Reuses the proven detection logic from ``extra_tests._test_whm`` but packaged
as an independent, reusable class for both TUI and headless CLI use.
"""

from __future__ import annotations

import asyncio
import logging
import re as _re
from typing import Callable, Optional

import httpx

logger = logging.getLogger(__name__)

# ── WHM detection constants ────────────────────────────────────────────────

WHM_MARKERS: tuple[str, ...] = (
    "whm",
    "web host manager",
    "cpanel",
    "whm-login",
    "cpsrvd",
    "cpsession",
    "cpsess",
    "login_theme",
    "security token",
    "server login",
    "powered by cpanel",
    "copyright cpanel",
)

WHM_PATHS: tuple[str, ...] = ("/", "/login", "/whm", "/cpanel")

# (port, use_https)
WHM_PORTS: tuple[tuple[int, bool], ...] = ((2087, True), (2086, False))

# ── Result type ────────────────────────────────────────────────────────────

WhmResult = dict  # {whm, hostname, target, port, path, possible, open_ports}


# ── Scanner class ──────────────────────────────────────────────────────────

class WhmScanner:
    """Batch WHM/cPanel scanner for direct IP probing.

    Parameters
    ----------
    concurrency:
        Maximum simultaneous HTTP probes (default 100).
    http_timeout:
        Total HTTP request timeout in seconds (default 8.0).
    tcp_timeout:
        TCP pre-check connection timeout in seconds (default 3.0).
    pause_event:
        Optional ``asyncio.Event`` for external pause/resume control.
    progress_callback:
        Optional async callable ``(ip, result)`` invoked after each probe.
    """

    def __init__(
        self,
        concurrency: int = 100,
        http_timeout: float = 8.0,
        tcp_timeout: float = 3.0,
        pause_event: Optional[asyncio.Event] = None,
        progress_callback: Optional[Callable] = None,
    ) -> None:
        self.concurrency = max(1, concurrency)
        self.http_timeout = http_timeout
        self.tcp_timeout = tcp_timeout
        self.pause_event = pause_event
        self.progress_callback = progress_callback

        self._sem: Optional[asyncio.Semaphore] = None
        self._client: Optional[httpx.AsyncClient] = None
        self._scanned: int = 0
        self._found: int = 0

    # ── Public API ─────────────────────────────────────────────────────

    @property
    def scanned(self) -> int:
        """Total IPs probed so far."""
        return self._scanned

    @property
    def found(self) -> int:
        """Total WHM-positive IPs found so far."""
        return self._found

    async def scan_batch(self, ips: list[str]) -> dict[str, WhmResult]:
        """Probe a batch of IPs for WHM and return results dict.

        Returns a dict mapping each IP to its result.  IPs that fail TCP
        pre-check or have no WHM markers still get an entry with ``whm=False``.
        """
        if not self._client:
            raise RuntimeError("WhmScanner.start() must be called before scan_batch()")

        tasks = [self._probe_one(ip) for ip in ips]
        results_list = await asyncio.gather(*tasks, return_exceptions=True)

        results: dict[str, WhmResult] = {}
        for ip, result in zip(ips, results_list):
            if isinstance(result, Exception):
                logger.debug(f"WHM probe error for {ip}: {result}")
                results[ip] = self._empty_result()
            else:
                results[ip] = result
                self._scanned += 1
                if result.get("whm"):
                    self._found += 1

        return results

    async def probe_single(self, ip: str) -> WhmResult:
        """Probe a single IP and return its WHM result."""
        if not self._client:
            raise RuntimeError("WhmScanner.start() must be called before probe_single()")
        return await self._probe_one(ip)

    async def start(self) -> None:
        """Initialise the shared HTTP client and semaphore."""
        self._sem = asyncio.Semaphore(self.concurrency)
        self._client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(self.http_timeout, connect=5.0),
            follow_redirects=True,
            limits=httpx.Limits(
                max_connections=self.concurrency,
                max_keepalive_connections=max(10, self.concurrency // 4),
            ),
            headers={"User-Agent": "Mozilla/5.0 PYDNS-WHM-Scanner/2.1"},
        )
        self._scanned = 0
        self._found = 0

    async def stop(self) -> None:
        """Close the shared HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
        self._sem = None

    # ── Internal ───────────────────────────────────────────────────────

    @staticmethod
    def _empty_result() -> WhmResult:
        return {
            "whm": False,
            "hostname": "",
            "target": "",
            "port": None,
            "path": "",
            "possible": False,
            "open_ports": [],
        }

    async def _tcp_port_open(self, target: str, port: int) -> bool:
        """Return True if a TCP connection to *target:port* succeeds."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self.tcp_timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            try:
                reader.feed_eof()
            except Exception:
                pass
            return True
        except Exception:
            return False

    @staticmethod
    def _extract_title(body: str) -> str:
        """Extract the HTML <title> from *body*, collapsed to one line."""
        m = _re.search(
            r"<title>\s*(.*?)\s*</title>", body, _re.IGNORECASE | _re.DOTALL
        )
        if not m:
            return ""
        return " ".join(m.group(1).split())[:120]

    async def _probe_one(self, ip: str) -> WhmResult:
        """Probe a single IP for WHM on ports 2087/2086."""
        # Respect external pause
        if self.pause_event:
            await self.pause_event.wait()

        result = self._empty_result()

        async with self._sem:  # type: ignore[union-attr]
            for port, use_https in WHM_PORTS:
                if not await self._tcp_port_open(ip, port):
                    continue

                result["open_ports"].append(f"{ip}:{port}")
                scheme = "https" if use_https else "http"

                for path in WHM_PATHS:
                    url = f"{scheme}://{ip}:{port}{path}"
                    try:
                        resp = await self._client.get(url)  # type: ignore[union-attr]
                        body = resp.text[:16384]
                        body_lc = body.lower()
                        final_url = str(resp.url).lower()

                        marker_found = any(m in body_lc for m in WHM_MARKERS)
                        url_hint = any(
                            t in final_url for t in ("cpsess", "whm", "cpanel")
                        )
                        status_hint = (
                            resp.status_code in (401, 403) and port in (2086, 2087)
                        )

                        if marker_found or url_hint:
                            hostname = self._extract_title(body)
                            result = {
                                "whm": True,
                                "hostname": hostname or "WHM Login",
                                "target": ip,
                                "port": port,
                                "path": path,
                                "possible": True,
                                "open_ports": result.get("open_ports", []),
                            }
                            # Found — stop probing this IP
                            if self.progress_callback:
                                await self.progress_callback(ip, result)
                            return result

                        if status_hint:
                            # Protected but on WHM port — mark as possible
                            result["possible"] = True
                            result["target"] = ip
                            result["port"] = port
                            result["path"] = path

                    except httpx.TimeoutException:
                        logger.debug(f"WHM timeout: {url}")
                    except httpx.ConnectError:
                        logger.debug(f"WHM connect error: {url}")
                    except Exception as exc:
                        logger.debug(f"WHM probe error for {url}: {exc}")

        # No WHM found
        if self.progress_callback:
            await self.progress_callback(ip, result)
        return result
#!/usr/bin/env python3
"""Dedicated WHM Scanner TUI.

A focused Textual interface for WHM/cPanel scanning that reuses the existing
WHM scanner engine and helper functions without changing the headless CLI.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

from textual import events
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widget import Widget
from textual.widgets import Button, DataTable, DirectoryTree, Header, Input, Label, RichLog, Select, Static

try:
    from .scanner import Checkbox, PlainDirectoryTree, VersionedFooter, _read_from_clipboard, logger
    from .scanner.whm_worker import WhmScanner, WhmResult
    from .whm_scan import _count_total_ips, _load_subnets, _stream_ips, save_whm_txt
except ImportError:
    from scanner import Checkbox, PlainDirectoryTree, VersionedFooter, _read_from_clipboard, logger
    from scanner.whm_worker import WhmScanner, WhmResult
    from whm_scan import _count_total_ips, _load_subnets, _stream_ips, save_whm_txt


class WHMStatsWidget(Widget):
    """Compact WHM-only statistics panel consistent with the PYDNS TUI style."""

    BAR_WIDTH = 38

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.total: int = 0
        self.scanned: int = 0
        self.whm: int = 0
        self.possible: int = 0
        self.errors: int = 0
        self.timeouts: int = 0
        self.speed: float = 0.0
        self.elapsed: float = 0.0
        self.status: str = "Idle"
        self.current_ip: str = ""

        self._w_header = Static("[b cyan]WHM Scanner Statistics[/b cyan]")
        self._w_gap = Static("")
        self._w_status = Static("")
        self._w_scan = Static("")
        self._w_now = Static("")
        self._w_found = Static("")
        self._w_errors = Static("")
        self._w_speed = Static("")
        self._w_time = Static("")
        self._w_gap2 = Static("")
        self._w_bar = Static("")

    def compose(self) -> ComposeResult:
        yield self._w_header
        yield self._w_gap
        yield self._w_status
        yield self._w_scan
        yield self._w_now
        yield self._w_found
        yield self._w_errors
        yield self._w_speed
        yield self._w_time
        yield self._w_gap2
        yield self._w_bar

    def update_stats(
        self,
        *,
        total: int | None = None,
        scanned: int | None = None,
        whm: int | None = None,
        possible: int | None = None,
        errors: int | None = None,
        timeouts: int | None = None,
        speed: float | None = None,
        elapsed: float | None = None,
        status: str | None = None,
        current_ip: str | None = None,
    ) -> None:
        if total is not None:
            self.total = total
        if scanned is not None:
            self.scanned = scanned
        if whm is not None:
            self.whm = whm
        if possible is not None:
            self.possible = possible
        if errors is not None:
            self.errors = errors
        if timeouts is not None:
            self.timeouts = timeouts
        if speed is not None:
            self.speed = speed
        if elapsed is not None:
            self.elapsed = elapsed
        if status is not None:
            self.status = status
        if current_ip is not None:
            self.current_ip = current_ip
        self._refresh_rows()

    def _refresh_rows(self) -> None:
        ratio = max(0.0, min(1.0, self.scanned / self.total)) if self.total else 0.0
        percent = ratio * 100
        filled = int(ratio * self.BAR_WIDTH)
        empty = max(0, self.BAR_WIDTH - filled)
        bar_str = (
            f"[#22c55e]{'█' * filled}[/#22c55e]"
            f"[grey35]{'░' * empty}[/grey35]"
            f" [bold cyan]{percent:5.1f}%[/bold cyan]"
        )
        scan_ratio = f"{self.scanned:,} / {self.total:,}" if self.total else f"{self.scanned:,} / [dim]—[/dim]"
        current_ip = self.current_ip or "[dim]—[/dim]"
        self._w_status.update(f"[yellow]Status:[/yellow] {self.status}")
        self._w_scan.update(f"[yellow]Scan:[/yellow]   {scan_ratio}")
        self._w_now.update(f"[yellow]Now:[/yellow]    {current_ip}")
        self._w_found.update(
            f"[yellow]WHM:[/yellow]    [#22c55e]{self.whm}[/#22c55e] confirmed"
            f" [dim]/[/dim] [#fbbf24]{self.possible}[/#fbbf24] possible"
        )
        self._w_errors.update(
            f"[yellow]Issues:[/yellow] [#ef4444]{self.errors}[/#ef4444] errors"
            f" [dim]/[/dim] [#fb923c]{self.timeouts}[/#fb923c] timeouts"
        )
        self._w_speed.update(f"[yellow]Speed:[/yellow]  {self.speed:.1f} IPs/sec")
        self._w_time.update(f"[yellow]Time:[/yellow]   {self.elapsed:.1f}s")
        self._w_bar.update(bar_str)


class WHMScannerTUI(App):
    """Dedicated WHM/cPanel Scanner TUI."""

    TITLE = "PYDNS WHM Scanner"
    ENABLE_COMMAND_PALETTE = False

    CSS = """
    Screen {
        background: #020805;
    }

    Header {
        background: #03140b;
        color: #00ff88;
    }

    Footer {
        background: #03140b;
        color: #00a85a;
    }

    Footer > .footer--key {
        background: #062214;
        color: #00ff88;
    }

    Footer > .footer--description {
        color: #9dffcb;
    }

    #start-screen {
        width: 100%;
        height: 100%;
        background: #020805;
        padding: 1;
    }

    #start-form {
        width: 100%;
        height: auto;
        max-height: 100%;
        border: solid #00a85a;
        background: #06120c;
        padding: 1 2;
        overflow-y: auto;
    }

    .form-row {
        width: 100%;
        height: auto;
        min-height: 3;
        margin: 0 0 1 0;
        align: left middle;
    }

    .field-label {
        width: 100%;
        text-align: center;
        content-align: center middle;
        color: #39ff88;
        padding: 0 0 1 0;
    }

    .form-field {
        width: 1fr;
        height: auto;
        padding: 0 1;
    }

    .target-file-field {
        width: 100%;
        height: auto;
        padding: 0;
    }

    Input {
        background: #04180d;
        border: solid #008f4c;
        color: #d6ffe8;
        height: 3;
    }

    Input:focus {
        border: solid #00ff88;
    }

    Select {
        width: 1fr;
        background: #04180d;
        border: solid #008f4c;
    }

    SelectCurrent {
        background: #04180d;
        color: #d6ffe8;
        padding: 0 1;
    }

    Select > SelectOverlay {
        background: #06120c;
        border: solid #00ff88;
        width: 100%;
    }

    Select > SelectOverlay > OptionList {
        background: #06120c;
        color: #d6ffe8;
        padding: 0;
        height: auto;
    }

    Select > SelectOverlay > OptionList > .option-list--option-highlighted {
        background: #06381f;
        color: #00ff88;
    }

    #file-browser-container {
        width: 100%;
        height: 10;
        max-height: 15;
        border: solid #00c96b;
        background: #06120c;
        margin: 1 0;
        display: none;
    }

    DirectoryTree {
        height: 100%;
        background: #06120c;
        color: #d6ffe8;
    }

    #advanced-container {
        width: 100%;
        height: auto;
        border: solid #008f4c;
        background: #020805;
        padding: 0 2;
        margin: 0 0 1 0;
    }

    #start-buttons {
        width: 100%;
        height: auto;
        align: center middle;
        margin-top: 2;
    }

    #scan-screen {
        width: 100%;
        height: 100%;
        background: #020805;
    }

    #stats-logs-container {
        width: 100%;
        height: 18;
    }

    #stats {
        width: 1fr;
        height: 100%;
        border: solid #00c96b;
        background: #06120c;
        padding: 1;
        margin: 1;
        color: #d6ffe8;
    }

    #logs {
        width: 1fr;
        height: 100%;
        border: solid #39ff88;
        background: #06120c;
        margin: 1;
        padding: 1;
    }

    #log-display {
        height: 100%;
    }

    #results {
        width: 100%;
        height: 1fr;
        background: #06120c;
        margin: 0 1;
        padding: 1;
    }

    #controls {
        width: 100%;
        height: auto;
        margin: 1;
        align: center middle;
    }

    Button {
        margin: 0 1;
        background: #04180d;
        color: #d6ffe8;
        border: solid #008f4c;
    }

    Button:hover {
        background: #06381f;
        color: #00ff88;
    }

    Button:focus {
        border: solid #00ff88;
    }

    Button.-primary {
        background: #00a85a;
        color: #001f10;
        border: solid #00ff88;
    }

    Button.-primary:hover {
        background: #00ff88;
    }

    DataTable {
        height: 100%;
        background: #06120c;
    }

    DataTable > .datatable--header {
        background: #04180d;
        color: #00ff88;
        text-style: bold;
    }

    DataTable > .datatable--cursor {
        background: #06381f;
        color: #d6ffe8;
    }

    RichLog {
        height: 100%;
        background: #06120c;
        color: #d6ffe8;
        scrollbar-size: 0 1;
    }

    Checkbox {
        background: transparent;
        color: #00c96b;
        margin-right: 2;
    }

    Checkbox > .toggle--button {
        background: transparent;
        border: solid #008f4c;
        color: #00c96b;
        width: 3;
    }

    Checkbox.-on {
        color: #d6ffe8;
    }

    Checkbox.-on > .toggle--button {
        background: #00a85a;
        border: solid #00ff88;
        color: #001f10;
    }

    .checkbox-row {
        align: center middle;
        height: auto;
        padding: 1 0;
    }
    """

    BINDINGS = [
        ("s", "start_scan", "Start"),
        ("q", "quit", "Quit"),
        ("p", "pause_scan", "Pause"),
        ("r", "resume_scan", "Resume"),
        ("c", "save_results", "Save"),
    ]

    def __init__(self):
        super().__init__()
        self.selected_cidr_file = ""
        self.subnet_file = ""
        self.output_path = ""
        self.concurrency = 100
        self.http_timeout = 10.0
        self.tcp_timeout = 5.0
        self.max_ips = 0
        self.verbose = True

        self.results: dict[str, WhmResult] = {}
        self.scanned = 0
        self.whm_count = 0
        self.possible_count = 0
        self.error_count = 0
        self.timeout_count = 0
        self.total_targets = 0
        self.start_time = 0.0
        self.scan_started = False
        self.is_paused = False
        self.shutdown_event: asyncio.Event | None = None
        self.pause_event: asyncio.Event | None = None
        self._stats_widget: WHMStatsWidget | None = None
        self._stats_timer = None
        self._processing_button = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)

        with Container(id="start-screen"):
            with Vertical(id="start-form"):
                with Vertical(classes="form-row target-file-field"):
                    yield Label("CIDR / Target File:", classes="field-label")
                    yield Select(
                        [
                            ("WHM Test Targets", "whm_test"),
                            ("Iran IPs", "iran"),
                            ("Indonesia Full", "indonesia"),
                            ("Indonesia Datacenter", "indonesia_dc"),
                            ("Custom File...", "custom"),
                        ],
                        value="whm_test",
                        allow_blank=False,
                        id="input-cidr-select",
                    )
                with Container(id="file-browser-container"):
                    yield PlainDirectoryTree(".", id="file-browser")

                with Container(id="advanced-container"):
                    with Horizontal(classes="form-row"):
                        with Vertical(classes="form-field"):
                            yield Label("Concurrency:", classes="field-label")
                            yield Input(value="100", placeholder="100", id="input-concurrency")
                        with Vertical(classes="form-field"):
                            yield Label("Max IPs (0=all):", classes="field-label")
                            yield Input(value="0", placeholder="0", id="input-max-ips")
                    with Horizontal(classes="form-row"):
                        with Vertical(classes="form-field"):
                            yield Label("HTTP Timeout (s):", classes="field-label")
                            yield Input(value="10", placeholder="10", id="input-http-timeout")
                        with Vertical(classes="form-field"):
                            yield Label("TCP Timeout (s):", classes="field-label")
                            yield Input(value="5", placeholder="5", id="input-tcp-timeout")
                    with Horizontal(classes="form-row checkbox-row"):
                        yield Checkbox("Verbose Log", value=True, id="input-verbose")

                with Horizontal(id="start-buttons"):
                    yield Button("Start WHM Scan", id="start-scan-btn", variant="success")
                    yield Button("Exit", id="exit-btn", variant="error")

        with Container(id="scan-screen"):
            with Horizontal(id="stats-logs-container"):
                yield WHMStatsWidget(id="stats")
                with Container(id="logs"):
                    yield RichLog(id="log-display", highlight=True, markup=True, max_lines=5000)
            with Container(id="results"):
                yield DataTable(id="results-table")
            with Horizontal(id="controls"):
                yield Button("⏸  Pause", id="pause-btn", variant="warning")
                yield Button("▶  Resume", id="resume-btn", variant="primary")
                yield Button("Save Results", id="save-btn", variant="success")
                yield Button("Quit", id="quit-btn", variant="error")

        yield VersionedFooter()

    def on_mount(self) -> None:
        self.dark = True
        self.query_one("#scan-screen").display = False
        self.query_one("#resume-btn", Button).display = False
        self._stats_widget = self.query_one("#stats", WHMStatsWidget)
        self._setup_table()

    def _setup_table(self) -> None:
        table = self.query_one("#results-table", DataTable)
        table.clear(columns=True)
        table.add_column("IP Address", key="ip")
        table.add_column("WHM", key="whm")
        table.add_column("Hostname", key="hostname", width=30)
        table.add_column("Port", key="port")
        table.add_column("Path", key="path")
        table.add_column("Open Ports", key="open_ports", width=24)
        table.cursor_type = "row"

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "input-cidr-select":
            browser = self.query_one("#file-browser-container")
            browser.display = event.value == "custom"

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        selected_file = str(event.path)
        self.selected_cidr_file = selected_file
        cidr_select = self.query_one("#input-cidr-select", Select)
        file_name = Path(selected_file).name
        cidr_select.set_options([
            ("WHM Test Targets", "whm_test"),
            ("Iran IPs", "iran"),
            ("Indonesia Full", "indonesia"),
            ("Indonesia Datacenter", "indonesia_dc"),
            ("Custom File...", "custom"),
            (file_name, "selected_file"),
        ])
        cidr_select.value = "selected_file"
        self.query_one("#file-browser-container").display = False
        self.notify(f"Selected: {file_name}", severity="information", timeout=3)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id in {"start-scan-btn", "pause-btn", "resume-btn"}:
            if self._processing_button:
                return
            self._processing_button = True
        try:
            if event.button.id == "start-scan-btn":
                self.action_start_scan()
            elif event.button.id == "exit-btn":
                self.action_quit()
            elif event.button.id == "pause-btn":
                self.action_pause_scan()
            elif event.button.id == "resume-btn":
                self.action_resume_scan()
            elif event.button.id == "save-btn":
                self.action_save_results()
            elif event.button.id == "quit-btn":
                self.action_quit()
        finally:
            if event.button.id in {"start-scan-btn", "pause-btn", "resume-btn"}:
                self._processing_button = False

    def on_key(self, event: events.Key) -> None:
        if event.key not in ("ctrl+v", "shift+insert", "meta+v"):
            return
        focused = self.focused
        if not isinstance(focused, Input):
            return
        pasted_text = _read_from_clipboard()
        if not pasted_text:
            return
        try:
            focused.insert_text_at_cursor(pasted_text)
            event.stop()
            self.notify("Pasted from clipboard", severity="information", timeout=1)
        except Exception as exc:
            logger.debug(f"Clipboard paste error: {exc}")

    def _resolve_cidr_file(self) -> str:
        cidr_value = self.query_one("#input-cidr-select", Select).value
        base = Path(__file__).parent
        if cidr_value == "whm_test":
            return str(base / "whm-test-targets.cidrs")
        if cidr_value == "iran":
            return str(base / "iran-ipv4.cidrs")
        if cidr_value == "indonesia":
            return str(base / "indonesia-ipv4.cidrs")
        if cidr_value == "indonesia_dc":
            return str(base / "indonesia-dc-ipv4.cidrs")
        if cidr_value == "selected_file" and self.selected_cidr_file:
            return self.selected_cidr_file
        raise ValueError("Please select a valid CIDR file")

    def _next_output_path(self) -> Path:
        """Return the next available automatic WHM output path."""
        output_dir = Path("results")
        output_dir.mkdir(parents=True, exist_ok=True)
        index = 1
        while True:
            output = output_dir / f"WHM_{index}.txt"
            if not output.exists():
                return output
            index += 1

    def _read_form(self) -> None:
        self.subnet_file = self._resolve_cidr_file()
        self.output_path = str(self._next_output_path())
        self.concurrency = max(1, int(self.query_one("#input-concurrency", Input).value.strip() or "100"))
        self.http_timeout = max(0.1, float(self.query_one("#input-http-timeout", Input).value.strip() or "10"))
        self.tcp_timeout = max(0.1, float(self.query_one("#input-tcp-timeout", Input).value.strip() or "5"))
        self.max_ips = max(0, int(self.query_one("#input-max-ips", Input).value.strip() or "0"))
        self.verbose = bool(self.query_one("#input-verbose", Checkbox).value)
        if not os.path.isfile(self.subnet_file):
            raise FileNotFoundError(f"CIDR file not found: {self.subnet_file}")

    def action_start_scan(self) -> None:
        if self.scan_started:
            return
        try:
            self._read_form()
        except Exception as exc:
            self.notify(str(exc), severity="error", timeout=4)
            return
        self.query_one("#start-screen").display = False
        self.query_one("#scan-screen").display = True
        self.query_one("#pause-btn", Button).display = True
        self.query_one("#resume-btn", Button).display = False
        self.run_worker(self._scan_async(), exclusive=True)

    def action_pause_scan(self) -> None:
        if not self.scan_started or self.is_paused:
            return
        self.is_paused = True
        if self.pause_event:
            self.pause_event.clear()
        self.query_one("#pause-btn", Button).display = False
        self.query_one("#resume-btn", Button).display = True
        self._log("[yellow]Scan paused[/yellow]")
        self._update_stats(status="Paused")

    def action_resume_scan(self) -> None:
        if not self.scan_started or not self.is_paused:
            return
        self.is_paused = False
        if self.pause_event:
            self.pause_event.set()
        self.query_one("#pause-btn", Button).display = True
        self.query_one("#resume-btn", Button).display = False
        self._log("[green]Scan resumed[/green]")
        self._update_stats(status="Running")

    def action_save_results(self) -> None:
        try:
            if not self.results:
                self.notify("No WHM results to save yet", severity="warning", timeout=3)
                return
            output = Path(self.output_path)
            output.parent.mkdir(parents=True, exist_ok=True)
            save_whm_txt(self.results, str(output))
            self._log(f"[green]✓ WHM results saved to: {output}[/green]")
            self.notify(f"Saved: {output}", severity="information", timeout=3)
        except Exception as exc:
            self._log(f"[red]Save failed: {exc}[/red]")
            self.notify(f"Save failed: {exc}", severity="error", timeout=4)

    def action_quit(self) -> None:
        if self.shutdown_event:
            self.shutdown_event.set()
        if self.pause_event:
            self.pause_event.set()
        try:
            self.workers.cancel_all()
        except Exception:
            pass
        self.exit()

    async def _scan_async(self) -> None:
        self.scan_started = True
        self.is_paused = False
        self.shutdown_event = asyncio.Event()
        self.pause_event = asyncio.Event()
        self.pause_event.set()
        self.results.clear()
        self.scanned = 0
        self.whm_count = 0
        self.possible_count = 0
        self.error_count = 0
        self.timeout_count = 0
        self.start_time = time.monotonic()
        self._setup_table()
        self._stats_timer = self.set_interval(0.5, self._tick_stats)

        try:
            self._log(f"[cyan]Loading CIDR file: {self.subnet_file}[/cyan]")
            loop = asyncio.get_running_loop()
            subnets = await loop.run_in_executor(None, _load_subnets, self.subnet_file)
            total_ips = _count_total_ips(subnets)
            self.total_targets = min(total_ips, self.max_ips) if self.max_ips > 0 else total_ips
            if self.total_targets <= 0:
                self._log("[red]No valid targets found in CIDR file[/red]")
                self.notify("No valid targets found", severity="error")
                return

            self._log(f"[cyan]Targets: {self.total_targets:,} | Concurrency: {self.concurrency} | HTTP: {self.http_timeout}s | TCP: {self.tcp_timeout}s[/cyan]")
            self._update_stats(status="Running", total=self.total_targets)

            scanner = WhmScanner(
                concurrency=self.concurrency,
                http_timeout=self.http_timeout,
                tcp_timeout=self.tcp_timeout,
                pause_event=self.pause_event,
                progress_callback=None,
            )
            await scanner.start()
            try:
                async for ip_batch in _stream_ips(subnets, self.concurrency, self.max_ips, self.shutdown_event):
                    if self.shutdown_event and self.shutdown_event.is_set():
                        break
                    if self.pause_event:
                        await self.pause_event.wait()
                    batch_results = await scanner.scan_batch(ip_batch)
                    for ip, result in batch_results.items():
                        self.scanned += 1
                        await self._process_result(ip, result)
                    self._update_stats(status="Running")
                    await asyncio.sleep(0)
            finally:
                await scanner.stop()

            self._update_stats(status="Finished")
            self._log(f"[green]Scan complete. WHM confirmed: {self.whm_count}, possible: {self.possible_count}[/green]")
            self.action_save_results()
            self.notify(f"WHM scan complete: {self.whm_count} found", severity="information", timeout=4)
        except asyncio.CancelledError:
            self._log("[yellow]Scan cancelled[/yellow]")
            self._update_stats(status="Cancelled")
        except Exception as exc:
            self.error_count += 1
            self._log(f"[red]Scan error: {exc}[/red]")
            self.notify(f"Scan error: {exc}", severity="error", timeout=5)
            self._update_stats(status="Error")
        finally:
            if self._stats_timer:
                self._stats_timer.stop()
                self._stats_timer = None
            self.scan_started = False
            self.query_one("#pause-btn", Button).display = False
            self.query_one("#resume-btn", Button).display = False

    async def _process_result(self, ip: str, result: WhmResult) -> None:
        self.results[ip] = result
        if result.get("whm"):
            self.whm_count += 1
            hostname = str(result.get("hostname", "") or "")
            port = result.get("port", "")
            self._add_result_row(ip, result, "[green]✓[/green]")
            self._log(f"[green]✓ WHM: {ip}:{port}{f' — {hostname}' if hostname else ''}[/green]")
        elif result.get("possible"):
            self.possible_count += 1
            self._add_result_row(ip, result, "[yellow]⚠[/yellow]")
            if self.verbose:
                self._log(f"[yellow]⚠ Possible WHM: {ip}:{result.get('port', '')}[/yellow]")
        else:
            open_ports = result.get("open_ports", []) or []
            if open_ports:
                self.error_count += 1
            else:
                self.timeout_count += 1
            if self.verbose and self.scanned % 25 == 0:
                self._log(f"[dim]Scanned {self.scanned:,}/{self.total_targets:,} — no WHM at {ip}[/dim]")
        self._update_stats(current_ip=ip)

    def _add_result_row(self, ip: str, result: WhmResult, whm_status: str) -> None:
        table = self.query_one("#results-table", DataTable)
        hostname = str(result.get("hostname", "") or "-")
        port = str(result.get("port", "") or "-")
        path = str(result.get("path", "") or "-")
        open_ports = ", ".join(result.get("open_ports", []) or []) or "-"
        try:
            if ip in table.rows:
                table.remove_row(ip)
        except Exception:
            pass
        table.add_row(ip, whm_status, hostname, port, path, open_ports, key=ip)

    def _tick_stats(self) -> None:
        status = "Paused" if self.is_paused else ("Running" if self.scan_started else "Idle")
        self._update_stats(status=status)

    def _update_stats(self, **overrides) -> None:
        if self._stats_widget is None:
            return
        elapsed = time.monotonic() - self.start_time if self.start_time else 0.0
        speed = self.scanned / elapsed if elapsed > 0 else 0.0
        self._stats_widget.update_stats(
            total=overrides.get("total", self.total_targets),
            scanned=overrides.get("scanned", self.scanned),
            whm=overrides.get("whm", self.whm_count),
            possible=overrides.get("possible", self.possible_count),
            errors=overrides.get("errors", self.error_count),
            timeouts=overrides.get("timeouts", self.timeout_count),
            speed=overrides.get("speed", speed),
            elapsed=overrides.get("elapsed", elapsed),
            status=overrides.get("status"),
            current_ip=overrides.get("current_ip"),
        )

    def _log(self, message: str) -> None:
        try:
            self.query_one("#log-display", RichLog).write(message)
        except Exception as exc:
            logger.debug(f"Could not write WHM TUI log: {exc}")


def main() -> None:
    """Run the dedicated WHM Scanner TUI."""
    app = WHMScannerTUI()
    app.run()


if __name__ == "__main__":
    main()

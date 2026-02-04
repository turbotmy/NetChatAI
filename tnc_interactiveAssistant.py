#!/usr/bin/env python3
"""Interactive Copilot chat assistant with Test-NetConnection monitoring."""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
import subprocess
import time
from itertools import count
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from statistics import mean
from typing import Any, Dict, List, Optional, Sequence, Tuple

from copilot import CopilotClient
from copilot.generated.session_events import SessionEventType
from numpy import var

DEFAULT_HOST = "8.8.8.8"
DEFAULT_MINUTES = 1
DEFAULT_INTERVAL_SECONDS = 5.0
DEFAULT_TIMEOUT_SECONDS = 5
DEFAULT_LATENCY_THRESHOLD_MS = 120
DEFAULT_LOG_DIR = "logs"
MAX_EVENTS_FOR_AI_PROMPT = 50

PING_LOG_PREFIX = "tnc"
ALERT_LOG_PREFIX = "tnc-alerts"
LOG_TIME_FORMAT = "%Y%m%d-%H%M%S"

LOSS_STREAK_MIN_LENGTH = 3
LATENCY_STREAK_MIN_LENGTH = 3
P95_PERCENTILE = 0.95

COMMAND_RUN = "/run"
COMMAND_ANALYSIS = "/analysis"
COMMAND_LIST = "/list"
COMMAND_HELP = "/help"
COMMAND_EXIT = "exit"
COMMAND_QUIT = "quit"

TASK_STATUS_RUNNING = "running"
TASK_STATUS_COMPLETED = "completed"
TASK_STATUS_FAILED = "failed"


@dataclass(frozen=True)
class TncEvent:
    """Represents a single Test-NetConnection result."""

    timestamp: str
    host: str
    success: bool
    latency_ms: Optional[float]
    error: Optional[str]


@dataclass(frozen=True)
class Streak:
    """Represents a streak of events matching a condition."""

    start_time: str
    end_time: str
    length: int


@dataclass
class BackgroundTask:
    """Represents a background TNC monitor task."""

    task_id: int
    host: str
    minutes: int
    threshold_ms: int
    started_at: str
    task: Optional[asyncio.Task] = None


BACKGROUND_TASKS: Dict[int, BackgroundTask] = {}
BACKGROUND_TASK_COUNTER = count(1)


def utc_now_iso() -> str:
    """Return the current UTC time in ISO 8601 format."""

    return datetime.now(timezone.utc).isoformat()


def ensure_log_dir(log_dir: str) -> None:
    """Ensure the log directory exists."""

    os.makedirs(log_dir, exist_ok=True)


def build_log_paths(log_dir: str) -> Tuple[str, str]:
    """Build log file paths for TNC logs."""

    timestamp = datetime.now(timezone.utc).strftime(LOG_TIME_FORMAT)
    tnc_log = os.path.join(log_dir, f"{PING_LOG_PREFIX}-{timestamp}.jsonl")
    alert_log = os.path.join(log_dir, f"{ALERT_LOG_PREFIX}-{timestamp}.jsonl")
    return tnc_log, alert_log


def run_powershell_json(command: str) -> Tuple[bool, str]:
    """Run a PowerShell command and return success flag and stdout text."""

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        return False, result.stderr.strip() or result.stdout.strip()

    return True, result.stdout.strip()


def parse_roundtrip_ms(payload: Dict) -> Optional[float]:
    """Extract round trip time from TNC JSON payload."""

    ping_details = payload.get("PingReplyDetails") or {}
    roundtrip = ping_details.get("RoundtripTime")
    if isinstance(roundtrip, (int, float)):
        return float(roundtrip)
    return None


def tnc_once(host: str, timeout_seconds: int) -> TncEvent:
    """Run Test-NetConnection once and return a TncEvent."""

    command = (
        "Test-NetConnection -ComputerName \"{host}\" "
        "-InformationLevel Detailed "
        "-WarningAction SilentlyContinue "
        "-ErrorAction SilentlyContinue "
        "| ConvertTo-Json -Depth 4"
    ).format(host=host)

    success, output = run_powershell_json(command)
    if not success:
        return TncEvent(
            timestamp=utc_now_iso(),
            host=host,
            success=False,
            latency_ms=None,
            error=output or "Test-NetConnection failed",
        )

    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        return TncEvent(
            timestamp=utc_now_iso(),
            host=host,
            success=False,
            latency_ms=None,
            error=f"Invalid JSON output: {exc}",
        )

    ping_succeeded = bool(payload.get("PingSucceeded", False))
    latency_ms = parse_roundtrip_ms(payload)
    error = None if ping_succeeded else "Ping failed"

    return TncEvent(
        timestamp=utc_now_iso(),
        host=host,
        success=ping_succeeded,
        latency_ms=latency_ms,
        error=error,
    )


def write_jsonl(path: str, payload: dict) -> None:
    """Append a JSON object to a JSONL file."""

    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True))
        handle.write("\n")


def should_alert(event: TncEvent, latency_threshold_ms: int) -> bool:
    """Return True when an event should trigger an alert."""

    if not event.success:
        return True
    if event.latency_ms is None:
        return True
    return event.latency_ms > latency_threshold_ms


def run_tnc_monitor(
    host: str,
    minutes: int,
    interval_seconds: float,
    latency_threshold_ms: int,
    timeout_seconds: int,
    log_dir: str,
) -> Tuple[str, str]:
    """Run the TNC monitor for the specified duration."""

    ensure_log_dir(log_dir)
    tnc_log, alert_log = build_log_paths(log_dir)

    end_time = time.monotonic() + (minutes * 60)
    while time.monotonic() < end_time:
        event = tnc_once(host, timeout_seconds)
        write_jsonl(tnc_log, asdict(event))

        if should_alert(event, latency_threshold_ms):
            write_jsonl(alert_log, asdict(event))
            print(
                f"ALERT {event.timestamp} host={event.host} "
                f"success={event.success} latency_ms={event.latency_ms} "
                f"error={event.error}"
            )

        time.sleep(interval_seconds)

    return tnc_log, alert_log


def load_events(paths: Sequence[str]) -> List[TncEvent]:
    """Load TNC events from JSONL paths."""

    events: List[TncEvent] = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                payload = json.loads(line)
                events.append(
                    TncEvent(
                        timestamp=payload.get("timestamp", ""),
                        host=payload.get("host", ""),
                        success=bool(payload.get("success", False)),
                        latency_ms=payload.get("latency_ms"),
                        error=payload.get("error"),
                    )
                )
    return events


def percentile(values: List[float], percentile_value: float) -> Optional[float]:
    """Return the percentile for a list of values."""

    if not values:
        return None
    if percentile_value <= 0:
        return min(values)
    if percentile_value >= 1:
        return max(values)

    sorted_values = sorted(values)
    index = int(math.ceil(percentile_value * len(sorted_values))) - 1
    return sorted_values[max(0, min(index, len(sorted_values) - 1))]


def find_streaks(
    events: List[TncEvent],
    predicate,
    min_length: int,
) -> List[Streak]:
    """Find streaks of events that satisfy the predicate."""

    streaks: List[Streak] = []
    current: List[TncEvent] = []

    for event in events:
        if predicate(event):
            current.append(event)
            continue

        if len(current) >= min_length:
            streaks.append(
                Streak(
                    start_time=current[0].timestamp,
                    end_time=current[-1].timestamp,
                    length=len(current),
                )
            )
        current = []

    if len(current) >= min_length:
        streaks.append(
            Streak(
                start_time=current[0].timestamp,
                end_time=current[-1].timestamp,
                length=len(current),
            )
        )

    return streaks


def format_streaks(label: str, streaks: List[Streak]) -> str:
    """Format streaks for display."""

    if not streaks:
        return f"{label}: none"
    lines = [f"{label}: {len(streaks)}"]
    for streak in streaks:
        lines.append(
            f"- {streak.start_time} to {streak.end_time} "
            f"({streak.length} events)"
        )
    return "\n".join(lines)


def analyze_logs(log_dir: str, latency_threshold_ms: int) -> None:
    """Analyze TNC logs and report patterns."""

    if not os.path.isdir(log_dir):
        print(f"Log directory not found: {log_dir}")
        return

    tnc_logs = [
        os.path.join(log_dir, path)
        for path in os.listdir(log_dir)
        if path.startswith(PING_LOG_PREFIX) and path.endswith(".jsonl")
    ]

    if not tnc_logs:
        print("No TNC logs found.")
        return

    events = load_events(sorted(tnc_logs))
    total = len(events)
    losses = [event for event in events if not event.success]
    latencies = [event.latency_ms for event in events if event.latency_ms is not None]

    loss_rate = (len(losses) / total) * 100 if total else 0.0
    avg_latency = mean(latencies) if latencies else None
    p95_latency = percentile(latencies, P95_PERCENTILE) if latencies else None

    print("Summary")
    print("-------")
    print(f"Total events: {total}")
    print(f"Losses: {len(losses)} ({loss_rate:.2f}%)")
    if avg_latency is not None:
        print(f"Average latency: {avg_latency:.2f} ms")
    if p95_latency is not None:
        print(f"P95 latency: {p95_latency:.2f} ms")

    loss_streaks = find_streaks(
        events,
        predicate=lambda event: not event.success,
        min_length=LOSS_STREAK_MIN_LENGTH,
    )
    high_latency_streaks = find_streaks(
        events,
        predicate=lambda event: event.latency_ms is not None
        and event.latency_ms > latency_threshold_ms,
        min_length=LATENCY_STREAK_MIN_LENGTH,
    )

    print()
    print("Patterns")
    print("--------")
    print(format_streaks("Loss streaks", loss_streaks))
    print(format_streaks("High latency streaks", high_latency_streaks))


def build_ai_analysis_context(
    log_dir: str,
    latency_threshold_ms: int,
) -> Optional[str]:
    """Build a prompt context for AI analysis of TNC logs."""

    if not os.path.isdir(log_dir):
        return None

    tnc_logs = [
        os.path.join(log_dir, path)
        for path in os.listdir(log_dir)
        if path.startswith(PING_LOG_PREFIX) and path.endswith(".jsonl")
    ]

    if not tnc_logs:
        return None

    events = load_events(sorted(tnc_logs))
    if not events:
        return None

    total = len(events)
    losses = [event for event in events if not event.success]
    latencies = [event.latency_ms for event in events if event.latency_ms is not None]
    loss_rate = (len(losses) / total) * 100 if total else 0.0
    avg_latency = mean(latencies) if latencies else None
    p95_latency = percentile(latencies, P95_PERCENTILE) if latencies else None

    loss_streaks = find_streaks(
        events,
        predicate=lambda event: not event.success,
        min_length=LOSS_STREAK_MIN_LENGTH,
    )
    high_latency_streaks = find_streaks(
        events,
        predicate=lambda event: event.latency_ms is not None
        and event.latency_ms > latency_threshold_ms,
        min_length=LATENCY_STREAK_MIN_LENGTH,
    )

    recent_events = events[-MAX_EVENTS_FOR_AI_PROMPT:]
    recent_lines = [
        (
            f"{event.timestamp} host={event.host} success={event.success} "
            f"latency_ms={event.latency_ms} error={event.error}"
        )
        for event in recent_events
    ]

    summary_lines = [
        "TNC log summary:",
        f"- Total events: {total}",
        f"- Losses: {len(losses)} ({loss_rate:.2f}%)",
    ]
    if avg_latency is not None:
        summary_lines.append(f"- Average latency: {avg_latency:.2f} ms")
    if p95_latency is not None:
        summary_lines.append(f"- P95 latency: {p95_latency:.2f} ms")

    summary_lines.append(
        f"- Loss streaks (>= {LOSS_STREAK_MIN_LENGTH}): {len(loss_streaks)}"
    )
    summary_lines.append(
        f"- High latency streaks (>= {LATENCY_STREAK_MIN_LENGTH}): "
        f"{len(high_latency_streaks)}"
    )

    return "\n".join(summary_lines + ["", "Recent events:"] + recent_lines)


def parse_run_command(command_text: str) -> Tuple[str, int, int]:
    """Parse /run command arguments."""

    match = re.search(
        r"/run\s+(?P<host>\S+)\s+(?P<minutes>\d+)\s+(?P<threshold>\d+)",
        command_text,
        flags=re.IGNORECASE,
    )
    if not match:
        return DEFAULT_HOST, DEFAULT_MINUTES, DEFAULT_LATENCY_THRESHOLD_MS

    host = match.group("host")
    minutes = int(match.group("minutes"))
    threshold = int(match.group("threshold"))
    return host, minutes, threshold


def get_task_status(task: asyncio.Task) -> str:
    """Return the status string for a background task."""

    if task.done():
        try:
            exception = task.exception()
        except asyncio.CancelledError:
            return TASK_STATUS_FAILED
        return TASK_STATUS_FAILED if exception else TASK_STATUS_COMPLETED
    return TASK_STATUS_RUNNING


async def run_monitor_background(task_info: BackgroundTask) -> None:
    """Run a TNC monitor task in the background."""

    try:
        tnc_log, alert_log = await asyncio.to_thread(
            run_tnc_monitor,
            task_info.host,
            task_info.minutes,
            DEFAULT_INTERVAL_SECONDS,
            task_info.threshold_ms,
            DEFAULT_TIMEOUT_SECONDS,
            DEFAULT_LOG_DIR,
        )
        print(
            f"\nBackground task {task_info.task_id} completed. "
            f"TNC log: {tnc_log} | Alert log: {alert_log}"
        )
    except Exception as exc:  # pragma: no cover - defensive logging
        print(
            f"\nBackground task {task_info.task_id} failed: {exc}"
        )


def start_background_task(host: str, minutes: int, threshold_ms: int) -> int:
    """Start a background task for TNC monitoring."""

    task_id = next(BACKGROUND_TASK_COUNTER)
    task_info = BackgroundTask(
        task_id=task_id,
        host=host,
        minutes=minutes,
        threshold_ms=threshold_ms,
        started_at=utc_now_iso(),
    )
    task = asyncio.create_task(run_monitor_background(task_info))
    task_info.task = task
    BACKGROUND_TASKS[task_id] = task_info
    return task_id


def print_menu() -> None:
    """Print available commands."""

    print("Commands:")
    print("  /run <host> <minutes> <threshold_ms>  Start monitoring")
    print("  /analysis                             Analyze log files")
    print("  /list                                 List background tasks")
    print("  /help                                 Show this help menu")
    print("  exit or quit                          Quit the assistant")


def is_command(text: str) -> bool:
    """Return True when the user input is a local command."""

    return text.strip().lower().startswith(
        (COMMAND_RUN, COMMAND_ANALYSIS, COMMAND_LIST, COMMAND_HELP,COMMAND_EXIT, COMMAND_QUIT)
    )


async def handle_analysis_command(session: Any) -> None:
    """Handle the /analysis command."""

    analyze_logs(log_dir=DEFAULT_LOG_DIR, latency_threshold_ms=DEFAULT_LATENCY_THRESHOLD_MS)

    context = build_ai_analysis_context(
        log_dir=DEFAULT_LOG_DIR,
        latency_threshold_ms=DEFAULT_LATENCY_THRESHOLD_MS,
    )
    if context is None:
        print("No log data available for AI observations.")
        return

    prompt = (
        "You are analyzing Test-NetConnection traffic logs. "
        "Provide AI observations of traffic patterns based on the summary and "
        "recent events. Return at least 1 bullet point.\n\n"
        f"{context}"
    )
    print("\nAI Observations:")
    await session.send_and_wait({"prompt": prompt})
    print()


def handle_list_command() -> None:
    """Handle the /list command."""

    if not BACKGROUND_TASKS:
        print("No background tasks.")
        return

    print("Background tasks:")
    for task_info in BACKGROUND_TASKS.values():
        if task_info.task is None:
            status = TASK_STATUS_FAILED
        else:
            status = get_task_status(task_info.task)
        print(
            f"- {task_info.task_id}: {status} host={task_info.host} "
            f"minutes={task_info.minutes} threshold_ms={task_info.threshold_ms} "
            f"started_at={task_info.started_at}"
        )


async def handle_run_command(command_text: str) -> None:
    """Handle the /run command by starting a background task."""

    host, minutes, threshold = parse_run_command(command_text)
    task_id = start_background_task(host, minutes, threshold)
    print(
        f"Background task {task_id} started: host={host}, "
        f"minutes={minutes}, threshold_ms={threshold}"
    )


def create_session(client: CopilotClient):
    """Create a Copilot chat session."""

    return client.create_session(
        {
            "model": "gpt-5.2-codex",
            "streaming": True,
        }
    )


def handle_event(event) -> None:
    """Stream assistant responses to stdout."""

    if event.type == SessionEventType.ASSISTANT_MESSAGE_DELTA:
        print(event.data.delta_content, end="", flush=True)
    if event.type == SessionEventType.SESSION_IDLE:
        print()


async def main() -> None:
    """Run the interactive assistant."""

    print("🌐  Test-NetConnection Assistant")

    client = CopilotClient()
    await client.start()

    """ Ping to verify connection """
    ping_response = await client.ping("hello")
    print("📡 Server connection verified (ping response received)\n")

    session = await create_session(client)
    print("✅ Session created! (ID: {session.SessionId})")
                      
    session.on(handle_event)
    print_menu()

    while True:
        try:
            user_input = await asyncio.to_thread(input, "Commands: ")

            if user_input.strip().lower() == COMMAND_EXIT or \
               user_input.strip().lower() == COMMAND_QUIT:
                break

            if user_input.strip().lower().startswith(COMMAND_RUN):
                await handle_run_command(user_input)
                continue

            if user_input.strip().lower().startswith(COMMAND_ANALYSIS):
                await handle_analysis_command(session)
                continue

            if user_input.strip().lower().startswith(COMMAND_LIST):
                handle_list_command()
                continue

            if user_input.strip().lower().startswith(COMMAND_HELP):
                print_menu()
                continue
            

        except EOFError:
            break
        except Exception as exc:
            print(f"Error processing command: {exc}")
            continue
        finally:
            pass
        
    await client.stop()


if __name__ == "__main__":
    asyncio.run(main())

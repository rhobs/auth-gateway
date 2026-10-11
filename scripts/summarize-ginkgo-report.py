#!/usr/bin/env python3
"""Summarize Ginkgo JSON reports and optional make-e2e timing sidecars."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


TIMING_START = "timing:start:"
TIMING_END = "timing:end:"
HOOK_TYPES = {
    "BeforeAll",
    "AfterAll",
    "BeforeEach",
    "AfterEach",
    "JustBeforeEach",
    "JustAfterEach",
}
EXECUTED_STATES = {"passed", "failed", "panicked", "aborted", "timedout"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path, help="Ginkgo JSON report files")
    return parser.parse_args()


def load_run(path: Path) -> dict[str, Any]:
    try:
        suites = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"could not read Ginkgo report {path}: {error}") from error
    if not isinstance(suites, list) or len(suites) != 1 or not isinstance(suites[0], dict):
        raise ValueError(f"expected one Ginkgo suite report in {path}")

    suite = suites[0]
    spec_reports = suite.get("SpecReports")
    if not isinstance(spec_reports, list):
        raise ValueError(f"Ginkgo report has no SpecReports array: {path}")
    specs = [report for report in spec_reports if isinstance(report, dict) and report.get("LeafNodeType") == "It"]
    if not specs:
        raise ValueError(f"Ginkgo report has no It specs: {path}")

    timing_path = path.with_name("timings.json")
    timings = None
    if timing_path.exists():
        try:
            timings = json.loads(timing_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"could not read timing sidecar {timing_path}: {error}") from error
        if not isinstance(timings, dict) or not isinstance(timings.get("stages"), dict):
            raise ValueError(f"timing sidecar has no stages object: {timing_path}")

    label = path.parent.name if path.parent.name not in {"", "."} else path.stem
    return {"path": path, "label": label, "suite": suite, "specs": specs, "timings": timings}


def report_location(report: dict[str, Any], field: str) -> tuple[str, int]:
    location = report.get(field)
    if not isinstance(location, dict):
        return "", 0
    filename = Path(str(location.get("FileName", ""))).name
    line = location.get("LineNumber", 0)
    return filename, line if isinstance(line, int) else 0


def container_hierarchy(report: dict[str, Any]) -> tuple[str, ...]:
    values = report.get("ContainerHierarchyTexts")
    if not isinstance(values, list):
        return ()
    return tuple(str(value) for value in values if value)


def container_name(report: dict[str, Any]) -> str:
    hierarchy = container_hierarchy(report)
    return hierarchy[0] if hierarchy else "(suite-level spec)"


def spec_key(report: dict[str, Any]) -> tuple[tuple[str, ...], str, str, int]:
    filename, line = report_location(report, "LeafNodeLocation")
    return container_hierarchy(report), str(report.get("LeafNodeText", "")), filename, line


def is_executed(report: dict[str, Any]) -> bool:
    return str(report.get("State", "")).lower() in EXECUTED_STATES


def duration_seconds(value: Any) -> float | None:
    if isinstance(value, (int, float)) and value >= 0:
        return float(value) / 1_000_000_000
    return None


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def event_time(event: dict[str, Any]) -> datetime | None:
    timeline = event.get("TimelineLocation")
    if isinstance(timeline, dict):
        return parse_time(timeline.get("Time"))
    return None


def timing_phases(report: dict[str, Any]) -> tuple[dict[str, list[float]], dict[str, int]]:
    events = report.get("SpecEvents")
    if not isinstance(events, list):
        return {}, {}

    active: dict[str, list[datetime | None]] = defaultdict(list)
    durations: dict[str, list[float]] = defaultdict(list)
    incomplete: dict[str, int] = defaultdict(int)
    ordered = sorted(
        (event for event in events if isinstance(event, dict)),
        key=lambda event: (event.get("TimelineLocation", {}).get("Order", 0)
                           if isinstance(event.get("TimelineLocation"), dict) else 0),
    )
    for event in ordered:
        if event.get("SpecEventType") != "By":
            continue
        message = event.get("Message")
        if not isinstance(message, str):
            continue
        if message.startswith(TIMING_START):
            active[message[len(TIMING_START):]].append(event_time(event))
        elif message.startswith(TIMING_END):
            name = message[len(TIMING_END):]
            if not active[name]:
                incomplete[name] += 1
                continue
            started = active[name].pop()
            finished = event_time(event)
            if started is None or finished is None or finished < started:
                incomplete[name] += 1
                continue
            durations[name].append((finished - started).total_seconds())

    for name, starts in active.items():
        if starts:
            incomplete[name] += len(starts)
    return dict(durations), {name: count for name, count in incomplete.items() if count > 0}


def hook_costs(report: dict[str, Any]) -> dict[tuple[str, str, int], float]:
    events = report.get("SpecEvents")
    if not isinstance(events, list):
        return {}
    totals: dict[tuple[str, str, int], float] = defaultdict(float)
    for event in events:
        if not isinstance(event, dict) or event.get("SpecEventType") != "Node (End)":
            continue
        node_type = event.get("NodeType")
        if not isinstance(node_type, str) or not (
            node_type in HOOK_TYPES or node_type.startswith("DeferCleanup")
        ):
            continue
        duration = duration_seconds(event.get("Duration"))
        if duration is None:
            continue
        filename, line = report_location(event, "CodeLocation")
        totals[(node_type, filename, line)] += duration
    return dict(totals)


def mark_container_edges(run: dict[str, Any]) -> dict[tuple[tuple[str, ...], str, str, int], set[str]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for report in run["specs"]:
        if is_executed(report):
            groups[container_name(report)].append(report)

    marks: dict[tuple[tuple[str, ...], str, str, int], set[str]] = defaultdict(set)
    for reports in groups.values():
        if not reports:
            continue
        first = min(reports, key=lambda report: parse_time(report.get("StartTime")) or datetime.max.astimezone())
        last = max(reports, key=lambda report: parse_time(report.get("EndTime")) or datetime.min.replace(tzinfo=datetime.now().astimezone().tzinfo))
        marks[spec_key(first)].add("first")
        marks[spec_key(last)].add("last")
    return dict(marks)


def format_seconds(seconds: float) -> str:
    if seconds >= 60:
        minutes = int(seconds // 60)
        remainder = seconds - minutes * 60
        return f"{minutes}m{remainder:04.1f}s"
    return f"{seconds:.3f}s"


def format_stats(values: list[float], present: int | None = None, total: int | None = None) -> str:
    if not values:
        return "unavailable"
    prefix = f"median {format_seconds(statistics.median(values))}"
    if len(values) > 1:
        prefix += f", range {format_seconds(min(values))}-{format_seconds(max(values))}"
    if present is not None and total is not None and present != total:
        prefix += f", data for {present}/{total} reports"
    elif len(values) == 1:
        prefix += " (1 report)"
    return prefix


def run_duration(run: dict[str, Any]) -> float | None:
    return duration_seconds(run["suite"].get("RunTime"))


def planned_count(run: dict[str, Any]) -> int | None:
    stats = run["suite"].get("PreRunStats")
    if isinstance(stats, dict):
        value = stats.get("SpecsThatWillRun")
        if isinstance(value, int):
            return value
    return None


def stage_duration(run: dict[str, Any], name: str) -> float | None:
    timings = run.get("timings")
    if not isinstance(timings, dict):
        return None
    stages = timings.get("stages")
    if not isinstance(stages, dict):
        return None
    stage = stages.get(name)
    if not isinstance(stage, dict):
        return None
    value = stage.get("durationSeconds")
    if isinstance(value, (int, float)) and value >= 0:
        return float(value)
    return None


def print_run_and_stage_summary(runs: list[dict[str, Any]]) -> None:
    print("Ginkgo report runs:")
    for run in runs:
        specs = run["specs"]
        states: dict[str, int] = defaultdict(int)
        for report in specs:
            states[str(report.get("State", "unknown")).lower()] += 1
        selected = planned_count(run)
        selected_text = str(selected) if selected is not None else "unknown"
        passed = states.get("passed", 0)
        failed = sum(count for state, count in states.items() if state in {"failed", "panicked", "aborted", "timedout"})
        skipped = states.get("skipped", 0)
        status = "passed" if run["suite"].get("SuiteSucceeded") else "failed"
        wall = run_duration(run)
        wall_text = format_seconds(wall) if wall is not None else "unknown"
        print(f"  {run['label']}: {status}, selected {selected_text}, passed {passed}, failed {failed}, skipped {skipped}, Ginkgo suite wall {wall_text}")

    wall_values = [duration for run in runs if (duration := run_duration(run)) is not None]
    print(f"Ginkgo suite wall time: {format_stats(wall_values, len(wall_values), len(runs))}")

    print("Make e2e stages (timings.json beside each report):")
    stage_names = [
        ("image-defaults", "image default generation"),
        ("cmctl", "cmctl tool setup"),
        ("cluster-setup", "Kind, cluster, and images setup"),
        ("framework-test", "framework test (build/cache lookup and test)"),
        ("e2e-compile", "e2e compile"),
        ("ginkgo-cli", "Ginkgo CLI wall"),
    ]
    sidecars = sum(run.get("timings") is not None for run in runs)
    if not sidecars:
        print(f"  stage timing unavailable for {len(runs)} report(s); older Ginkgo reports may not have a timing sidecar")
        return

    setup_values: list[float] = []
    for run in runs:
        values = [stage_duration(run, name) for name in ("image-defaults", "cmctl", "cluster-setup")]
        if all(value is not None for value in values):
            setup_values.append(sum(value for value in values if value is not None))
    print(f"  setup total (image defaults + cmctl + cluster setup): {format_stats(setup_values, len(setup_values), len(runs))}")
    for stage_name, label in stage_names:
        values = [value for run in runs if (value := stage_duration(run, stage_name)) is not None]
        if values:
            print(f"  {label}: {format_stats(values, len(values), len(runs))}")


def build_spec_records(runs: list[dict[str, Any]]) -> tuple[dict[Any, list[dict[str, Any] | None]], dict[str, dict[int, tuple[float, int]]]]:
    by_spec: dict[Any, list[dict[str, Any] | None]] = {}
    container_totals: dict[str, dict[int, tuple[float, int]]] = defaultdict(dict)
    for run_index, run in enumerate(runs):
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for report in run["specs"]:
            key = spec_key(report)
            by_spec.setdefault(key, [None] * len(runs))[run_index] = report
            if is_executed(report):
                grouped[container_name(report)].append(report)
        for container, reports in grouped.items():
            total = sum(duration_seconds(report.get("RunTime")) or 0 for report in reports)
            container_totals[container][run_index] = (total, len(reports))
    return by_spec, container_totals


def display_spec_name(key: tuple[tuple[str, ...], str, str, int], outer: str) -> str:
    hierarchy, text, filename, line = key
    nested = " / ".join(hierarchy[1:])
    name = f"{nested} / {text}" if nested else text
    if filename and line:
        name += f" ({filename}:{line})"
    return name or "(unnamed spec)"


def print_container_summary(container_totals: dict[str, dict[int, tuple[float, int]]], total_runs: int) -> None:
    print("Container runtimes (sum of inclusive spec runtimes, including edge-hook cost):")
    for container in sorted(container_totals):
        values = [total for total, _ in container_totals[container].values()]
        counts = [count for _, count in container_totals[container].values()]
        count_text = str(counts[0]) if len(set(counts)) == 1 else f"{min(counts)}-{max(counts)}"
        print(f"  {container}: {count_text} specs, {format_stats(values, len(values), total_runs)}")


def print_spec_details(runs: list[dict[str, Any]], by_spec: dict[Any, list[dict[str, Any] | None]]) -> None:
    edges = [mark_container_edges(run) for run in runs]
    print("Specs (RunTime is inclusive of Ginkgo hooks; phase rows use explicit timing markers):")
    ordered = sorted(by_spec, key=lambda key: (key[0][0] if key[0] else "", key[3], key[1]))
    current_container: str | None = None
    for key in ordered:
        hierarchy, _, _, _ = key
        container = hierarchy[0] if hierarchy else "(suite-level spec)"
        if container != current_container:
            current_container = container
            print(f"  {container}:")

        records = by_spec[key]
        timed_reports = [record for record in records if record is not None and is_executed(record)]
        runtime_values = [duration for record in timed_reports if (duration := duration_seconds(record.get("RunTime"))) is not None]
        if runtime_values:
            runtime_text = format_stats(runtime_values, len(runtime_values), len(runs))
        else:
            runtime_text = "not run in these reports"

        first_runs = sum("first" in edge.get(key, set()) for edge in edges)
        last_runs = sum("last" in edge.get(key, set()) for edge in edges)
        markers = []
        if first_runs:
            markers.append("first" if first_runs == len(runs) else f"first in {first_runs}/{len(runs)}")
        if last_runs:
            markers.append("last" if last_runs == len(runs) else f"last in {last_runs}/{len(runs)}")
        prefix = f"[{', '.join(markers)}] " if markers else ""
        print(f"    {prefix}{display_spec_name(key, container)}: {runtime_text}")

        hooks_by_key: dict[tuple[str, str, int], list[float]] = defaultdict(list)
        phases_by_name: dict[str, list[float]] = defaultdict(list)
        incomplete_by_name: dict[str, int] = defaultdict(int)
        for record in records:
            if record is None or not is_executed(record):
                continue
            for hook, duration in hook_costs(record).items():
                hooks_by_key[hook].append(duration)
            phases, incomplete = timing_phases(record)
            for name, durations in phases.items():
                phases_by_name[name].append(sum(durations))
            for name, count in incomplete.items():
                incomplete_by_name[name] += count

        if hooks_by_key:
            items = []
            for (hook, filename, line), values in sorted(hooks_by_key.items()):
                label = hook
                if filename and line:
                    label += f"@{filename}:{line}"
                items.append(f"{label} {format_stats(values)}")
            print("      hooks: " + "; ".join(items))
        if phases_by_name:
            items = [f"{name} {format_stats(values, len(values), len(runs))}" for name, values in sorted(phases_by_name.items())]
            print("      phases: " + "; ".join(items))
        for name, count in sorted(incomplete_by_name.items()):
            print(f"      phase incomplete: {name} ({count} missing or unmatched marker(s))")


def main() -> int:
    args = parse_args()
    try:
        runs = [load_run(path) for path in args.reports]
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2

    print(f"Ginkgo timing summary for {len(runs)} report(s)")
    print_run_and_stage_summary(runs)
    by_spec, container_totals = build_spec_records(runs)
    print_container_summary(container_totals, len(runs))
    print_spec_details(runs, by_spec)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

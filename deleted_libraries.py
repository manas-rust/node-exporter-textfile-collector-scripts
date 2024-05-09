#!/usr/bin/env python3
"""
Script to count the number of deleted libraries that are linked by running
processes and expose a summary as Prometheus metrics.

The aim is to discover processes that are still using libraries that have since
been updated, perhaps due security vulnerabilities.
"""

import errno
import glob
import os
import sys
from collections import defaultdict
from typing import Dict, Any
from prometheus_client import CollectorRegistry, Gauge, generate_latest


def process_maps_entry(
    path: str, line_parts: list, processes_linking_deleted_libraries: dict
):
    if len(line_parts) != 7:
        return
    library = line_parts[5]
    comment = line_parts[6]

    if "/lib/" in library and "(deleted)" in comment:
        if path not in processes_linking_deleted_libraries:
            processes_linking_deleted_libraries[path] = defaultdict(int)
        processes_linking_deleted_libraries[path].setdefault(library, 0)
        processes_linking_deleted_libraries[path][library] += 1


def count_processes_per_library(
    processes_linking_deleted_libraries: Dict[str, Dict[str, Any]],
) -> Dict[str, int]:
    num_processes_per_library = defaultdict(int)

    for process, library_count in processes_linking_deleted_libraries.items():
        # Skip the process if its value is not a dictionary
        if not isinstance(library_count, dict):
            continue

        for library in library_count:
            num_processes_per_library.setdefault(library, 0)
            num_processes_per_library[library] += 1

    return num_processes_per_library


def main():
    processes_linking_deleted_libraries = defaultdict(lambda: defaultdict(int))

    for path in glob.glob("/proc/*/maps"):
        try:
            with open(path, "rb") as file:
                for line in file:
                    process_maps_entry(
                        path,
                        line.decode().strip().split(),
                        processes_linking_deleted_libraries,
                    )
        except (EnvironmentError, PermissionError) as e:
            if e.errno != errno.ENOENT:
                sys.exit(f"Failed to open file: {path}")

    num_processes_per_library = count_processes_per_library(
        processes_linking_deleted_libraries
    )

    registry = CollectorRegistry()
    g = Gauge(
        "node_processes_linking_deleted_libraries",
        "Count of running processes that link a deleted library",
        ["library_path", "library_name"],
        registry=registry,
    )

    for library, count in num_processes_per_library.items():
        dir_path, basename = os.path.split(library)
        g.labels(dir_path, basename).set(count)

    print(generate_latest(registry).decode(), end="")


if __name__ == "__main__":
    main()

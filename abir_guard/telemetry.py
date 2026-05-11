"""OpenTelemetry integration facade for Abir-Guard.

If OpenTelemetry packages are not installed, this module gracefully degrades to
in-memory counters while preserving a stable API.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, Generator, Optional


@dataclass
class OperationMetric:
    name: str
    success: bool
    duration_ms: float


class VaultTelemetry:
    """Telemetry helper for metrics and tracing."""

    def __init__(self, service_name: str = "abir-guard", enable_otel: bool = True):
        self.service_name = service_name
        self.enable_otel = enable_otel
        self._metrics: Dict[str, int] = {}
        self._last_error: Optional[str] = None
        self._tracer = None

        if enable_otel:
            try:
                from opentelemetry import trace  # type: ignore

                self._tracer = trace.get_tracer(service_name)
            except Exception as exc:
                self._last_error = str(exc)
                self._tracer = None

    @contextmanager
    def span(self, name: str) -> Generator[None, None, None]:
        """Create a trace span if OpenTelemetry is available."""
        if self._tracer is None:
            yield
            return

        with self._tracer.start_as_current_span(name):
            yield

    def record_operation(self, metric: OperationMetric) -> None:
        key = f"{metric.name}:{'ok' if metric.success else 'err'}"
        self._metrics[key] = self._metrics.get(key, 0) + 1

    def track(self, name: str, success: bool = True, started_at: Optional[float] = None) -> None:
        now = time.perf_counter()
        start = started_at if started_at is not None else now
        duration_ms = (now - start) * 1000.0
        self.record_operation(OperationMetric(name=name, success=success, duration_ms=duration_ms))

    def snapshot(self) -> Dict[str, int]:
        return dict(self._metrics)

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

"""
Phase 4 Performance Benchmarking utilities.

Provides practical throughput benchmarks for core vault crypto operations
and cloud-envelope encryption paths, with a helper for the 10k ops/sec
target called out in the Phase 4 roadmap.
"""

import asyncio
import os
import time
from dataclasses import dataclass
from typing import Callable, Optional

from . import HybridEncryptor
from .cloud_kms import CloudKmsEnvelope, LocalMockKmsBackend


@dataclass
class BenchmarkResult:
    """Single benchmark run result."""

    name: str
    iterations: int
    total_seconds: float
    operations_per_second: float


class Phase4Benchmark:
    """Benchmark runner for Phase 4 performance objectives."""

    def __init__(self):
        self._encryptor = HybridEncryptor()

    async def run_vault_roundtrip(
        self,
        iterations: int = 20_000,
        concurrency: int = 64,
        payload_size: int = 128,
    ) -> BenchmarkResult:
        """
        Benchmark in-memory encrypt+decrypt roundtrips.

        Each iteration performs one encrypt + one decrypt cycle.
        """
        if iterations <= 0:
            raise ValueError("iterations must be > 0")
        if concurrency <= 0:
            raise ValueError("concurrency must be > 0")
        if payload_size <= 0:
            raise ValueError("payload_size must be > 0")

        keypair, shared = self._encryptor.generate_keypair()
        sem = asyncio.Semaphore(concurrency)

        async def one_roundtrip() -> None:
            payload = os.urandom(payload_size)
            async with sem:
                ct = self._encryptor.encrypt(payload, keypair)
                pt = self._encryptor.decrypt(ct, shared)
                if pt != payload:
                    raise RuntimeError("roundtrip verification failed")

        started = time.perf_counter()
        await asyncio.gather(*(one_roundtrip() for _ in range(iterations)))
        elapsed = time.perf_counter() - started

        return BenchmarkResult(
            name="vault_roundtrip",
            iterations=iterations,
            total_seconds=elapsed,
            operations_per_second=iterations / elapsed if elapsed > 0 else 0.0,
        )

    async def run_envelope_roundtrip(
        self,
        iterations: int = 10_000,
        concurrency: int = 32,
        payload_size: int = 1024,
    ) -> BenchmarkResult:
        """Benchmark cloud-envelope encryption/decryption with mock KMS."""
        if iterations <= 0:
            raise ValueError("iterations must be > 0")
        if concurrency <= 0:
            raise ValueError("concurrency must be > 0")
        if payload_size <= 0:
            raise ValueError("payload_size must be > 0")

        backend = LocalMockKmsBackend("phase4-benchmark-key")
        envelope = CloudKmsEnvelope(provider="mock", key_id="phase4-benchmark-key", backend=backend)
        sem = asyncio.Semaphore(concurrency)

        async def one_roundtrip() -> None:
            payload = os.urandom(payload_size)
            async with sem:
                ct = envelope.encrypt(payload)
                pt = envelope.decrypt(ct)
                if pt != payload:
                    raise RuntimeError("envelope roundtrip verification failed")

        started = time.perf_counter()
        await asyncio.gather(*(one_roundtrip() for _ in range(iterations)))
        elapsed = time.perf_counter() - started

        return BenchmarkResult(
            name="cloud_envelope_roundtrip",
            iterations=iterations,
            total_seconds=elapsed,
            operations_per_second=iterations / elapsed if elapsed > 0 else 0.0,
        )

    @staticmethod
    def meets_target(result: BenchmarkResult, target_ops_per_second: int = 10_000) -> bool:
        """Return True when benchmark throughput reaches Phase 4 target."""
        if target_ops_per_second <= 0:
            raise ValueError("target_ops_per_second must be > 0")
        return result.operations_per_second >= target_ops_per_second


def run_sync(coro_factory: Callable[[], asyncio.Future]) -> BenchmarkResult:
    """Synchronous helper for CLI/scripts."""
    return asyncio.run(coro_factory())

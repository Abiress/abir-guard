"""Phase 4 performance benchmarking tests."""

import asyncio


class TestPhase4Benchmark:
    """Validate benchmark runner behavior and target checks."""

    def setup_method(self):
        from abir_guard.performance_benchmark import Phase4Benchmark

        self.Phase4Benchmark = Phase4Benchmark

    def test_vault_roundtrip_benchmark_runs(self):
        bench = self.Phase4Benchmark()
        result = asyncio.run(
            bench.run_vault_roundtrip(iterations=200, concurrency=16, payload_size=64)
        )

        assert result.name == "vault_roundtrip"
        assert result.iterations == 200
        assert result.total_seconds > 0
        assert result.operations_per_second > 0

    def test_envelope_roundtrip_benchmark_runs(self):
        bench = self.Phase4Benchmark()
        result = asyncio.run(
            bench.run_envelope_roundtrip(iterations=100, concurrency=8, payload_size=128)
        )

        assert result.name == "cloud_envelope_roundtrip"
        assert result.iterations == 100
        assert result.total_seconds > 0
        assert result.operations_per_second > 0

    def test_target_check(self):
        bench = self.Phase4Benchmark()
        from abir_guard.performance_benchmark import BenchmarkResult

        result = BenchmarkResult(
            name="test",
            iterations=10_000,
            total_seconds=0.5,
            operations_per_second=20_000.0,
        )
        assert bench.meets_target(result, target_ops_per_second=10_000) is True
        assert bench.meets_target(result, target_ops_per_second=50_000) is False

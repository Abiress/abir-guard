"""Phase 6 WASM/edge deployment manifest helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass
class WasmTarget:
    name: str
    runtime: str
    entrypoint: str


class WasmEdgeBuilder:
    """Generate deployment specs for browser and edge runtimes."""

    def __init__(self):
        self.targets = {
            "browser": WasmTarget("browser", "web", "abir_guard_wasm.js"),
            "deno": WasmTarget("deno", "deno", "mod.ts"),
            "cloudflare": WasmTarget("cloudflare", "workers", "worker.js"),
        }

    def target_spec(self, target: str) -> Dict[str, str]:
        if target not in self.targets:
            raise ValueError(f"unsupported target: {target}")
        t = self.targets[target]
        return {
            "target": t.name,
            "runtime": t.runtime,
            "entrypoint": t.entrypoint,
            "wasm_module": "abir_guard_bg.wasm",
            "memory_model": "zero-copy",
        }

    def all_specs(self) -> Dict[str, Dict[str, str]]:
        return {k: self.target_spec(k) for k in self.targets}

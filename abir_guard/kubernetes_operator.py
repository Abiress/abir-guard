"""Kubernetes operator utilities for Abir-Guard deployment patterns.

This module provides manifest builders for sidecar injection, rotation jobs,
and Helm value templates used in cloud-native deployment workflows.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class SidecarConfig:
    image: str = "ghcr.io/abiress/abir-guard:latest"
    container_name: str = "abir-guard-sidecar"
    port: int = 9090
    cpu_request: str = "100m"
    memory_request: str = "128Mi"
    cpu_limit: str = "500m"
    memory_limit: str = "512Mi"


@dataclass
class RotationPolicy:
    schedule: str = "*/30 * * * *"
    max_keys_per_run: int = 100


class KubernetesOperator:
    """Build Kubernetes resources required for enterprise operations."""

    @staticmethod
    def build_sidecar_container(config: SidecarConfig) -> Dict:
        return {
            "name": config.container_name,
            "image": config.image,
            "ports": [{"containerPort": config.port, "name": "mcp-http"}],
            "resources": {
                "requests": {
                    "cpu": config.cpu_request,
                    "memory": config.memory_request,
                },
                "limits": {
                    "cpu": config.cpu_limit,
                    "memory": config.memory_limit,
                },
            },
            "env": [{"name": "ABIR_GUARD_API_KEY", "valueFrom": {"secretKeyRef": {"name": "abir-guard-secrets", "key": "apiKey"}}}],
        }

    @staticmethod
    def build_sidecar_injection_patch(config: SidecarConfig) -> List[Dict]:
        return [
            {
                "op": "add",
                "path": "/spec/template/spec/containers/-",
                "value": KubernetesOperator.build_sidecar_container(config),
            }
        ]

    @staticmethod
    def build_rotation_cronjob(namespace: str, policy: RotationPolicy, image: str) -> Dict:
        return {
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": "abir-guard-rotation", "namespace": namespace},
            "spec": {
                "schedule": policy.schedule,
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "restartPolicy": "OnFailure",
                                "containers": [
                                    {
                                        "name": "rotation",
                                        "image": image,
                                        "args": ["rotate", "--max-keys", str(policy.max_keys_per_run)],
                                    }
                                ],
                            }
                        }
                    }
                },
            },
        }

    @staticmethod
    def build_helm_values(config: SidecarConfig, policy: RotationPolicy) -> Dict:
        return {
            "image": {"repository": config.image.split(":")[0], "tag": config.image.split(":")[-1]},
            "service": {"port": config.port},
            "resources": {
                "requests": {"cpu": config.cpu_request, "memory": config.memory_request},
                "limits": {"cpu": config.cpu_limit, "memory": config.memory_limit},
            },
            "rotation": {
                "enabled": True,
                "schedule": policy.schedule,
                "maxKeysPerRun": policy.max_keys_per_run,
            },
        }

"""Scan configuration: dataclass + YAML/CLI loading. No secrets in config files."""
from __future__ import annotations
import os
from dataclasses import dataclass, field

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

INTENSITY_LIMITS = {
    "low": {"payloads_per_param": 3, "delay": 0.5},
    "medium": {"payloads_per_param": 8, "delay": 0.1},
    "high": {"payloads_per_param": 20, "delay": 0.0},
}


@dataclass
class ScanConfig:
    target_url: str = ""
    depth: int = 2
    workers: int = 10
    delay: float = 0.1
    max_requests: int = 2000
    timeout: int = 10
    verify_tls: bool = True
    intensity: str = "medium"
    user_agent: str = "Spyder-Strick/2.0 (authorized security assessment)"
    authorize: bool = False
    allow_hosts: list = field(default_factory=list)
    auth: str = ""          # "user:pass" or "Bearer <token>"
    cookies: str = ""       # "k=v; k2=v2"
    openapi: str = ""
    sast_path: str = ""
    ai_provider: str = "none"   # none | ollama | openai
    ai_model: str = ""
    ai_base_url: str = ""
    output_dir: str = "reports"
    formats: list = field(default_factory=lambda: ["json", "html", "csv"])

    def __post_init__(self):
        if self.intensity not in INTENSITY_LIMITS:
            self.intensity = "medium"
        self.depth = max(0, int(self.depth))
        self.workers = max(1, min(50, int(self.workers)))
        self.timeout = max(1, int(self.timeout))

    @property
    def payload_limit(self) -> int:
        return INTENSITY_LIMITS[self.intensity]["payloads_per_param"]

    @classmethod
    def from_yaml(cls, path: str, **overrides):
        data = {}
        if path and os.path.exists(path):
            if yaml is None:
                raise RuntimeError("pyyaml is required to load a YAML config file")
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}
        data.update({k: v for k, v in overrides.items() if v is not None})
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self):
        return {k: v for k, v in self.__dict__.items()}

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuthContext:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass
class TimeoutsConfig:
    request_seconds: int = 10


@dataclass
class RequestDefaultsConfig:
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class EndpointSourcesConfig:
    openapi: str | None = None
    include_paths: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)


@dataclass
class ReportingConfig:
    format: str = "markdown"
    output: str = "report.md"
    include_request_headers: bool = False
    include_response_headers: bool = True
    max_body_chars: int = 500


@dataclass
class ChecksConfig:
    enabled: list[str] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class AppConfig:
    base_url: str
    timeouts: TimeoutsConfig = field(default_factory=TimeoutsConfig)
    request_defaults: RequestDefaultsConfig = field(default_factory=RequestDefaultsConfig)
    auth_contexts: list[AuthContext] = field(default_factory=list)
    endpoint_sources: EndpointSourcesConfig = field(default_factory=EndpointSourcesConfig)
    checks: ChecksConfig = field(default_factory=ChecksConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
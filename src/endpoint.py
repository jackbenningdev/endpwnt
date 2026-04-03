from dataclasses import dataclass, field
from typing import Any

HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

@dataclass
class Endpoint:
    method: str
    path: str
    summary: str | None = None
    operation_id: str | None = None
    parameters: list[dict[str, Any]] = field(default_factory=list)
    request_body: dict[str, Any] | None = None
    security: list[dict[str, Any]] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)

    def path_param_names(self) -> list[str]:
        return [
            p.get("name", "")
            for p in self.parameters
            if p.get("in") == "path" and p.get("name")
        ]

    def query_param_names(self) -> list[str]:
        return [
            p.get("name", "")
            for p in self.parameters
            if p.get("in") == "query" and p.get("name")
        ]

    def requires_auth_in_spec(self) -> bool:
        return bool(self.security)

    def format_path(self, replacements: dict[str, str] | None = None) -> str:
        path = self.path
        for name in self.path_param_names():
            value = (replacements or {}).get(name, "1")
            path = path.replace(f"{{{name}}}", str(value))
        return path
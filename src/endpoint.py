from dataclasses import dataclass, field
from typing import Any

@dataclass
class EndPoint:
    method: str
    path: str
    summary: str | None = None
    operation_id: str | None = None
    parameters: list[dict[str, Any]] = field(default_factory=list)
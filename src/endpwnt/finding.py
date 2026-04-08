from dataclasses import dataclass, field
from typing import Any

@dataclass
class Finding:
    check_id: str
    severity: str
    title: str
    endpoint: str
    auth_context: str | None
    evidence: str
    recommendation: str
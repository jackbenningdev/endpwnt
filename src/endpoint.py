from dataclasses import dataclass, field
from typing import Any

@dataclass
class EndPoint:
    method: str
    path: str
    summary: str
    operation_id: str
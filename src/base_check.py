from abc import ABC, abstractmethod
from endpoint import EndPoint
from client import HttpClient

class BaseCheck(ABC):

    check_id = "base"

    @abstractmethod
    def applies_to(self, endpoint: EndPoint) -> bool:
        raise NotImplementedError

    @abstractmethod
    def run(self, endpoint: EndPoint, client, auth_contexts, options: dict) -> bool:
        raise NotImplementedError

    def run_other_methods(self, endpoint:EndPoint, client:HttpClient, auth_context):
        findings = []
        METHODS_TO_PROBE = ["OPTIONS", "PUT", "PATCH", "DELETE"]
        for method in METHODS_TO_PROBE:
            if method == endpoint.method.upper():
                continue

            probe_endpoint = EndPoint(
                method=method,
                path=endpoint.path,
                summary=endpoint.summary,
                operation_id=endpoint.operation_id,
            )

            resp = client.send(probe_endpoint, auth_context=auth_context)

            if resp is None:
                continue

            if resp.status_code not in (400, 401, 403, 404, 405):
                findings.append({
                    "title": "Potential unexpected method exposure",
                    "endpoint": endpoint.path,
                    "documented_method": endpoint.method,
                    "probed_method": method,
                    "status_code": resp.status_code,
                })

        return findings

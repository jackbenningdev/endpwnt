from abc import ABC, abstractmethod
from typing import List

from endpwnt.client import HttpClient
from endpwnt.endpoint import EndPoint

class BaseCheck(ABC):

    check_id = "base"

    @abstractmethod
    def applies_to(self, endpoint: EndPoint) -> bool:
        raise NotImplementedError

    @abstractmethod
    def run(self, endpoint: EndPoint, client, auth_contexts, options: dict) -> list:
        raise NotImplementedError

    def run_other_methods(self, endpoint:EndPoint, client:HttpClient, auth_context) -> List[dict[str, str]]:
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
                parameters=endpoint.parameters,
            )

            path_params = {name: "1" for name in endpoint.path_param_names()} or None
            resp = client.send(probe_endpoint, auth_context, path_params=path_params)

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

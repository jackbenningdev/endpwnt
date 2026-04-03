from pathlib import Path
from parse_config import *
from typing import Any
from endpoint import EndPoint
import yaml


class EndPwnt:
    def __init__(self, openapi_path, config_path):
        try:
            with open(Path(openapi_path), "r", encoding="utf-8") as f:
                spec = yaml.safe_load(f)

            self.endpoints: list[EndPoint] = []

            for path, path_item in spec.get("paths", {}).items():
                path_parameters = path_item.get("parameters", [])

                for method, details in path_item.items():
                    if method == "parameters":
                        continue

                    if method.lower() not in {"get", "post", "put", "patch", "delete", "options", "head"}:
                        continue

                    operation_parameters = details.get("parameters", [])
                    all_parameters = path_parameters + operation_parameters

                    self.endpoints.append(
                        EndPoint(
                            method=method.upper(),
                            path=path,
                            summary=details.get("summary"),
                            operation_id=details.get("operationId"),
                            parameters=all_parameters,
                        )
                    )

        except Exception as e:
            print("ERROR: Could not import openAPI")
            raise e

        try:
            raw = yaml.safe_load(Path(config_path).read_text())
            checks_raw = raw.get("checks", {})
            enabled = checks_raw.get("enabled", [])
            options = {k: v for k, v in checks_raw.items() if k != "enabled"}

            self.app_config = AppConfig(
                base_url=raw["base_url"],
                timeouts=TimeoutsConfig(**raw.get("timeouts", {})),
                request_defaults=RequestDefaultsConfig(**raw.get("request_defaults", {})),
                auth_contexts=[AuthContext(**x) for x in raw.get("auth_contexts", [])],
                endpoint_sources=EndpointSourcesConfig(**raw.get("endpoint_sources", {})),
                checks=ChecksConfig(enabled=enabled, options=options),
                reporting=ReportingConfig(**raw.get("reporting", {})),
            )
            print(self.app_config)

        except Exception as e:
            print("ERROR: could not import config")
            raise e


    def get_endpoints(self):
        return self.endpoints

    def print_endpoints(self):
        for endpoint in self.endpoints:
            print(endpoint)



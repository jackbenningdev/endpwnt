from pathlib import Path
from parse_config import *
from typing import Any
from endpoint import EndPoint
import yaml


class EndPwnt:
    def __init__(self, openapi_path: str, config_path: str) -> None:
        self.endpoints = self._load_openapi(openapi_path)
        self.app_config = self._load_config(config_path)

    def _load_openapi(self, openapi_path: str) -> list[EndPoint]:
        try:
            with open(Path(openapi_path), "r", encoding="utf-8") as f:
                spec = yaml.safe_load(f)
        except Exception as e:
            raise RuntimeError(f"Could not import OpenAPI spec: {e}") from e

        endpoints: list[EndPoint] = []

        for path, path_item in spec.get("paths", {}).items():
            if not isinstance(path_item, dict):
                continue

            path_parameters = path_item.get("parameters", [])

            for method, details in path_item.items():
                if method == "parameters":
                    continue
                if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}:
                    continue
                if not isinstance(details, dict):
                    continue

                operation_parameters = details.get("parameters", [])
                all_parameters = path_parameters + operation_parameters

                endpoints.append(
                    EndPoint(
                        method=method.upper(),
                        path=path,
                        summary=details.get("summary"),
                        operation_id=details.get("operationId"),
                        parameters=all_parameters,
                        request_body=details.get("requestBody"),
                        security=details.get("security", []),
                        tags=details.get("tags", []),
                    )
                )

        return endpoints

    def _load_config(self, config_path: str) -> AppConfig:
        try:
            raw = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
            checks_raw = raw.get("checks", {})
            enabled = checks_raw.get("enabled", [])
            options = {k: v for k, v in checks_raw.items() if k != "enabled"}

            return AppConfig(
                base_url=raw["base_url"],
                timeouts=TimeoutsConfig(**raw.get("timeouts", {})),
                request_defaults=RequestDefaultsConfig(**raw.get("request_defaults", {})),
                auth_contexts=[AuthContext(**x) for x in raw.get("auth_contexts", [])],
                endpoint_sources=EndpointSourcesConfig(**raw.get("endpoint_sources", {})),
                checks=ChecksConfig(enabled=enabled, options=options),
                reporting=ReportingConfig(**raw.get("reporting", {})),
            )
        except Exception as e:
            raise RuntimeError(f"Could not import config: {e}") from e
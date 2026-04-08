import textwrap
from pathlib import Path

import pytest

from endpwnt.scanner import EndPwnt


def _write(p: Path, content: str) -> None:
    p.write_text(textwrap.dedent(content), encoding="utf-8")


@pytest.fixture
def scan_workspace(tmp_path: Path) -> Path:
    """Lay down a minimal config + openapi pair and return the config path."""
    _write(tmp_path / "openapi.yaml", """
        openapi: 3.0.0
        info:
          title: Test API
          version: 1.0.0
        paths:
          /users/{id}:
            parameters:
              - name: id
                in: path
                required: true
                schema: { type: integer }
            get:
              operationId: getUser
              summary: Fetch a user
              security:
                - bearerAuth: []
              tags: [users]
            delete:
              operationId: deleteUser
          /health:
            get:
              operationId: health
          /ignored:
            get:
              operationId: ignored
    """)

    _write(tmp_path / "config.yaml", """
        base_url: http://localhost:8000
        timeouts:
          request_seconds: 5
        request_defaults:
          headers:
            User-Agent: endpwnt-tests
        auth_contexts:
          - name: unauth
          - name: alice
            headers:
              Authorization: Bearer alice-token
        endpoint_sources:
          openapi: openapi.yaml
          exclude_paths:
            - /ignored
        checks:
          enabled: [auth, bola]
          bola:
            test_values: ["1", "2"]
        reporting:
          format: html
          output: report.html
    """)

    return tmp_path / "config.yaml"


def test_endpwnt_loads_endpoints_from_openapi(scan_workspace: Path):
    pwnt = EndPwnt(str(scan_workspace))
    paths_methods = sorted((ep.method, ep.path) for ep in pwnt.endpoints)
    assert ("GET", "/users/{id}") in paths_methods
    assert ("DELETE", "/users/{id}") in paths_methods
    assert ("GET", "/health") in paths_methods


def test_endpwnt_honors_excluded_paths(scan_workspace: Path):
    pwnt = EndPwnt(str(scan_workspace))
    assert all(ep.path != "/ignored" for ep in pwnt.endpoints)


def test_endpwnt_loads_app_config_fields(scan_workspace: Path):
    pwnt = EndPwnt(str(scan_workspace))
    cfg = pwnt.app_config

    assert cfg.base_url == "http://localhost:8000"
    assert cfg.timeouts.request_seconds == 5
    assert cfg.request_defaults.headers["User-Agent"] == "endpwnt-tests"

    auth_names = [ctx.name for ctx in cfg.auth_contexts]
    assert auth_names == ["unauth", "alice"]
    assert cfg.auth_contexts[1].headers["Authorization"] == "Bearer alice-token"

    assert cfg.checks.enabled == ["auth", "bola"]
    assert cfg.checks.options["bola"]["test_values"] == ["1", "2"]
    assert cfg.reporting.format == "html"


def test_endpwnt_propagates_path_parameters_to_operations(scan_workspace: Path):
    pwnt = EndPwnt(str(scan_workspace))
    user_get = next(
        ep for ep in pwnt.endpoints
        if ep.path == "/users/{id}" and ep.method == "GET"
    )
    assert user_get.path_param_names() == ["id"]
    assert user_get.requires_auth_in_spec() is True


def test_endpwnt_discovers_check_classes(scan_workspace: Path):
    pwnt = EndPwnt(str(scan_workspace))
    discovered = {cls.check_id for cls in pwnt.checks_classes}
    # Sanity: at least the well-known checks were registered.
    assert {"auth", "bola", "method_exposure", "error_leak", "token_lifecycle"} <= discovered


def test_endpwnt_raises_runtime_error_on_missing_config(tmp_path: Path):
    with pytest.raises(RuntimeError, match="Could not import config"):
        EndPwnt(str(tmp_path / "does-not-exist.yaml"))


def test_endpwnt_raises_runtime_error_on_missing_openapi(tmp_path: Path):
    cfg = tmp_path / "config.yaml"
    _write(cfg, """
        base_url: http://localhost:8000
        endpoint_sources:
          openapi: missing.yaml
        checks:
          enabled: []
    """)
    with pytest.raises(RuntimeError, match="Could not import OpenAPI spec"):
        EndPwnt(str(cfg))

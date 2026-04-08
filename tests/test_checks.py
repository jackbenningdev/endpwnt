from endpwnt.checks import (
    AuthCheck,
    BolaCheck,
    ErrorLeakCheck,
    MethodExposureCheck,
    TokenLifeCycleCheck,
)
from endpwnt.endpoint import EndPoint


def _ep(method="GET", path="/users/{id}", parameters=None) -> EndPoint:
    return EndPoint(method=method, path=path, parameters=parameters or [])


# ---- AuthCheck.applies_to -------------------------------------------------

def test_auth_check_applies_to_protected_route():
    assert AuthCheck().applies_to(_ep(path="/users/{id}")) is True


def test_auth_check_skips_public_routes():
    public_paths = [
        "/health", "/metrics", "/docs", "/openapi.json",
        "/login", "/register",
    ]
    check = AuthCheck()
    for p in public_paths:
        assert check.applies_to(_ep(path=p)) is False, p


def test_auth_check_is_case_insensitive_for_public_marker():
    assert AuthCheck().applies_to(_ep(path="/HEALTH")) is False


# ---- BolaCheck.applies_to -------------------------------------------------

def test_bola_check_applies_when_path_has_id_segment():
    ep = _ep(path="/users/{id}", parameters=[{"name": "id", "in": "path"}])
    assert BolaCheck().applies_to(ep) is True


def test_bola_check_applies_when_query_has_id_param():
    ep = _ep(path="/orders", parameters=[{"name": "order_id", "in": "query"}])
    assert BolaCheck().applies_to(ep) is True


def test_bola_check_skips_endpoints_without_object_identifiers():
    ep = _ep(path="/search", parameters=[{"name": "q", "in": "query"}])
    assert BolaCheck().applies_to(ep) is False


# ---- MethodExposureCheck.applies_to ---------------------------------------

def test_method_exposure_check_applies_only_to_get_and_post():
    check = MethodExposureCheck()
    assert check.applies_to(_ep(method="GET")) is True
    assert check.applies_to(_ep(method="POST")) is True
    assert check.applies_to(_ep(method="DELETE")) is False
    assert check.applies_to(_ep(method="OPTIONS")) is False


# ---- ErrorLeakCheck.applies_to --------------------------------------------

def test_error_leak_check_applies_to_everything():
    check = ErrorLeakCheck()
    assert check.applies_to(_ep(path="/health")) is True
    assert check.applies_to(_ep(path="/users/{id}")) is True


# ---- TokenLifeCycleCheck.applies_to ---------------------------------------

def test_token_lifecycle_check_matches_token_related_paths():
    check = TokenLifeCycleCheck()
    for p in ["/auth/refresh", "/logout", "/oauth/token", "/session"]:
        assert check.applies_to(_ep(path=p)) is True, p


def test_token_lifecycle_check_ignores_unrelated_paths():
    assert TokenLifeCycleCheck().applies_to(_ep(path="/users/{id}")) is False

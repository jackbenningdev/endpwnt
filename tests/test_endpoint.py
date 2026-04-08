from endpwnt.endpoint import EndPoint


def _ep(**overrides) -> EndPoint:
    defaults = dict(method="GET", path="/users/{id}")
    defaults.update(overrides)
    return EndPoint(**defaults)


def test_path_param_names_extracts_only_path_params():
    ep = _ep(parameters=[
        {"name": "id", "in": "path"},
        {"name": "limit", "in": "query"},
        {"name": "X-Trace", "in": "header"},
    ])
    assert ep.path_param_names() == ["id"]


def test_query_param_names_extracts_only_query_params():
    ep = _ep(parameters=[
        {"name": "id", "in": "path"},
        {"name": "limit", "in": "query"},
        {"name": "offset", "in": "query"},
    ])
    assert ep.query_param_names() == ["limit", "offset"]


def test_param_helpers_skip_entries_missing_name():
    ep = _ep(parameters=[{"in": "path"}, {"name": "", "in": "path"}])
    assert ep.path_param_names() == []


def test_requires_auth_in_spec_true_when_security_present():
    ep = _ep(security=[{"bearerAuth": []}])
    assert ep.requires_auth_in_spec() is True


def test_requires_auth_in_spec_false_when_security_empty():
    assert _ep().requires_auth_in_spec() is False


def test_format_path_substitutes_named_params():
    ep = _ep(path="/users/{id}/orders/{orderId}", parameters=[
        {"name": "id", "in": "path"},
        {"name": "orderId", "in": "path"},
    ])
    assert ep.format_path({"id": "42", "orderId": "7"}) == "/users/42/orders/7"


def test_format_path_defaults_missing_replacements_to_one():
    ep = _ep(path="/users/{id}", parameters=[{"name": "id", "in": "path"}])
    assert ep.format_path() == "/users/1"
    assert ep.format_path({}) == "/users/1"


def test_format_path_no_op_when_no_path_params():
    ep = _ep(path="/health", parameters=[])
    assert ep.format_path({"id": "99"}) == "/health"

from base_check import BaseCheck
from endpoint import EndPoint
from finding import Finding


def _default_path_params(endpoint: EndPoint) -> dict[str, str] | None:
    names = endpoint.path_param_names()
    if not names:
        return None
    return {name: "1" for name in names}


def _pick_auth_contexts(auth_contexts, *, include_unauth: bool = True):
    if include_unauth:
        return auth_contexts
    return [ctx for ctx in auth_contexts if ctx.name != "unauth"]


class AuthCheck(BaseCheck):
    check_id = "auth"

    def applies_to(self, endpoint: EndPoint) -> bool:
        public_ish = ["/health", "/metrics", "/docs", "/openapi", "/login", "/register"]
        return not any(x in endpoint.path.lower() for x in public_ish)

    def run(self, endpoint: EndPoint, client, auth_contexts, options: dict) -> list[Finding]:
        findings: list[Finding] = []

        unauth_ctx = next((ctx for ctx in auth_contexts if ctx.name == "unauth"), None)
        if unauth_ctx is None:
            return findings

        resp = client.send(endpoint, unauth_ctx, path_params=_default_path_params(endpoint))
        if resp is None:
            return findings

        if resp.status_code < 300:
            findings.append(
                Finding(
                    check_id=self.check_id,
                    severity="high" if endpoint.requires_auth_in_spec() else "medium",
                    title="EndPoint accessible without authentication",
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    auth_context=unauth_ctx.name,
                    evidence=(
                        f"Unauthenticated request returned HTTP {resp.status_code} "
                        f"for endpoint expected to require access control."
                    ),
                    recommendation=(
                        "Require authentication and authorization checks before returning "
                        "protected resources."
                    ),
                )
            )

        return findings


class BolaCheck(BaseCheck):
    check_id = "bola"
    DEFAULT_ID_NAMES = {
        "id", "userid", "user_id", "accountid", "account_id",
        "orderid", "order_id", "profileid", "profile_id"
    }

    def applies_to(self, endpoint: EndPoint) -> bool:
        param_names = {p.get("name", "").lower() for p in endpoint.parameters}
        if any(name in self.DEFAULT_ID_NAMES for name in param_names):
            return True
        return bool(endpoint.path_param_names())

    def run(self, endpoint: EndPoint, client, auth_contexts, options: dict) -> list[Finding]:
        findings: list[Finding] = []

        id_names = {
            name.lower()
            for name in options.get("candidate_param_names", list(self.DEFAULT_ID_NAMES))
        }
        test_values = [str(v) for v in options.get("test_values", ["1", "2"])]

        candidate_names = [
            p.get("name")
            for p in endpoint.parameters
            if p.get("name") and p.get("name", "").lower() in id_names
        ]
        if not candidate_names:
            candidate_names = endpoint.path_param_names()

        if not candidate_names or len(test_values) < 2:
            return findings

        privileged_contexts = [ctx for ctx in auth_contexts if ctx.name != "unauth"]
        if not privileged_contexts:
            return findings

        first_name = candidate_names[0]
        value_a, value_b = test_values[0], test_values[1]

        for ctx in privileged_contexts:
            path_params_a = {name: value_a for name in endpoint.path_param_names()}
            path_params_b = {name: value_b for name in endpoint.path_param_names()}

            query_params_a = None
            query_params_b = None
            if first_name not in endpoint.path_param_names():
                query_params_a = {first_name: value_a}
                query_params_b = {first_name: value_b}

            resp_a = client.send(endpoint, ctx, path_params=path_params_a, query_params=query_params_a)
            resp_b = client.send(endpoint, ctx, path_params=path_params_b, query_params=query_params_b)

            if not resp_a or not resp_b:
                continue

            same_success_bucket = resp_a.status_code < 300 and resp_b.status_code < 300
            materially_different = (resp_a.text or "") != (resp_b.text or "")

            if same_success_bucket and materially_different:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity="medium",
                        title="Potential BOLA exposure",
                        endpoint=f"{endpoint.method} {endpoint.path}",
                        auth_context=ctx.name,
                        evidence=(
                            f"Two object identifiers ({value_a} vs {value_b}) both returned success "
                            f"for auth context '{ctx.name}', and response bodies differed."
                        ),
                        recommendation=(
                            "Verify object-level authorization on this route. Ensure the caller is "
                            "allowed to access the referenced object, not just authenticated."
                        ),
                    )
                )

        return findings


class MethodExposureCheck(BaseCheck):
    check_id = "method_exposure"

    def applies_to(self, endpoint: EndPoint) -> bool:
        return endpoint.method in {"GET", "POST"}

    def run(self, endpoint: EndPoint, client, auth_contexts, options: dict) -> list[Finding]:
        findings: list[Finding] = []

        for ctx in auth_contexts:
            for raw in self.run_other_methods(endpoint, client, ctx):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity="medium",
                        title="Potential unexpected method exposure",
                        endpoint=f"{endpoint.method} {endpoint.path}",
                        auth_context=ctx.name,
                        evidence=(
                            f"Documented method is {raw['documented_method']}, but probing with "
                            f"{raw['probed_method']} returned HTTP {raw['status_code']}."
                        ),
                        recommendation=(
                            "Confirm only intended HTTP methods are enabled. Explicitly deny "
                            "unsupported methods with 405 where possible."
                        ),
                    )
                )

        return findings


class ErrorLeakCheck(BaseCheck):
    check_id = "error_leak"

    def applies_to(self, endpoint: EndPoint) -> bool:
        return True

    def run(self, endpoint: EndPoint, client, auth_contexts, options: dict) -> list[Finding]:
        findings: list[Finding] = []
        leak_markers = [
            "traceback", "exception", "stack trace", "sql", "psycopg", "sqlite",
            "mysql", "postgres", "mongo", "redis", "nullreference", "keyerror"
        ]

        for ctx in auth_contexts:
            resp = client.send(
                endpoint,
                ctx,
                path_params=_default_path_params(endpoint),
                query_params={"__endpwnt_probe": "'\"<invalid>"},
                json_body={"__endpwnt_probe": "'\"<invalid>"},
            )

            if not resp:
                continue

            body = (resp.text or "").lower()
            if resp.status_code >= 500 and any(marker in body for marker in leak_markers):
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        severity="medium",
                        title="Verbose error details exposed",
                        endpoint=f"{endpoint.method} {endpoint.path}",
                        auth_context=ctx.name,
                        evidence=(
                            f"HTTP {resp.status_code} response contained framework/database/debug "
                            "indicators in the body."
                        ),
                        recommendation=(
                            "Return generic server errors to clients and log detailed exception "
                            "data only on the server side."
                        ),
                    )
                )

        return findings


class TokenLifeCycleCheck(BaseCheck):
    check_id = "token_lifecycle"

    def applies_to(self, endpoint: EndPoint) -> bool:
        path = endpoint.path.lower()
        return any(x in path for x in ["refresh", "logout", "token", "session", "auth"])

    def run(self, endpoint: EndPoint, client, auth_contexts, options: dict) -> list[Finding]:
        findings: list[Finding] = []
        path = endpoint.path.lower()

        privileged_contexts = [ctx for ctx in auth_contexts if ctx.name != "unauth"]
        if not privileged_contexts:
            return findings

        for ctx in privileged_contexts:
            if "logout" in path:
                before = client.send(endpoint, ctx, path_params=_default_path_params(endpoint))
                after = client.send(endpoint, ctx, path_params=_default_path_params(endpoint))

                if before and after and before.status_code < 500 and after.status_code < 300:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity="medium",
                            title="Possible logout/token invalidation weakness",
                            endpoint=f"{endpoint.method} {endpoint.path}",
                            auth_context=ctx.name,
                            evidence=(
                                "Repeated authenticated use still succeeded after invoking a logout-related route."
                            ),
                            recommendation=(
                                "Invalidate session state or refresh tokens on logout and verify "
                                "revocation is enforced server-side."
                            ),
                        )
                    )

            elif "refresh" in path:
                first = client.send(endpoint, ctx, path_params=_default_path_params(endpoint))
                second = client.send(endpoint, ctx, path_params=_default_path_params(endpoint))

                if first and second and first.status_code < 300 and second.status_code < 300:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            severity="low",
                            title="Refresh flow allows repeated reuse",
                            endpoint=f"{endpoint.method} {endpoint.path}",
                            auth_context=ctx.name,
                            evidence=(
                                "Refresh-related endpoint succeeded multiple times with the same auth context."
                            ),
                            recommendation=(
                                "Review whether refresh tokens are rotated, bounded, and invalidated "
                                "after use where appropriate."
                            ),
                        )
                    )

        return findings
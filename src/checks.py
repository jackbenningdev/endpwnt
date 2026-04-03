from base_check import BaseCheck
from endpoint import EndPoint
from finding import Finding

class AuthCheck(BaseCheck):

    def applies_to(self, endpoint:EndPoint):
        PUBLICISH = ["/health", "/metrics", "/docs", "/openapi", "/login", "/register"]
        if any(x in endpoint.path.lower() for x in PUBLICISH):
            return False
        return True

    def run(self, endpoint, client, auth_contexts):
        pass


class BolaCheck(BaseCheck):
    check_id = "bola"

    DEFAULT_ID_NAMES = {"id", "userid", "user_id", "accountid", "account_id", "orderid", "order_id", "profileid",
                        "profile_id"}

    def applies_to(self, endpoint: EndPoint) -> bool:
        param_names = {p.get("name", "").lower() for p in endpoint.parameters}
        if any(name in self.DEFAULT_ID_NAMES for name in param_names):
            return True
        return bool(endpoint.path_param_names())

    def run(self, endpoint: EndPoint, client, auth_contexts, options: dict) -> Finding:
        result = []

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
            return result

        privileged_contexts = [ctx for ctx in auth_contexts if ctx.name != "unauth"]
        if len(privileged_contexts) < 1:
            return result

        for ctx in privileged_contexts:
            first_name = candidate_names[0]
            value_a, value_b = test_values[0], test_values[1]

            path_params_a = {name: value_a for name in endpoint.path_param_names()}
            path_params_b = {name: value_b for name in endpoint.path_param_names()}
            query_params_a = {first_name: value_a} if first_name not in endpoint.path_param_names() else None
            query_params_b = {first_name: value_b} if first_name not in endpoint.path_param_names() else None

            resp_a = client.send(endpoint, ctx, path_params=path_params_a, query_params=query_params_a)
            resp_b = client.send(endpoint, ctx, path_params=path_params_b, query_params=query_params_b)

            if not resp_a or not resp_b:
                continue

            same_success_bucket = (resp_a.status_code < 300) and (resp_b.status_code < 300)
            materially_different = (resp_a.text or "") != (resp_b.text or "")

            if same_success_bucket and materially_different:
                result.append(
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
                            "Verify object-level authorization on this route. Ensure the caller is allowed "
                            "to access the referenced object, not just authenticated."
                        ),
                    )
                )

        return result


class MethodExposureCheck(BaseCheck):
    def applies_to(self, endpoint:EndPoint):
        return endpoint.method in {"GET", "POST"}

    def run(self, endpoint, client, auth_contexts):
        pass

class ErrorLeakCheck(BaseCheck):
    def applies_to(self, endpoint:EndPoint):
        return True

    def run(self, endpoint, client, auth_contexts):
        pass


class TokenLifeCycleCheck(BaseCheck):
    def applies_to(self, endpoint:EndPoint):
        path = endpoint.path.lower()
        return any(x in path for x in ["refresh", "logout", "token", "session", "auth"])

    def run(self, endpoint, client, auth_contexts):
        pass
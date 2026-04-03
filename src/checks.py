from base_check import BaseCheck
from endpoint import EndPoint

class AuthCheck(BaseCheck):

    def applies_to(self, endpoint):
        PUBLICISH = ["/health", "/metrics", "/docs", "/openapi", "/login", "/register"]
        if any(x in endpoint.path.lower() for x in PUBLICISH):
            return False
        return True

    def run(self, endpoint, client, auth_contexts):
        pass


class BolaCheck(BaseCheck):

    def applies_to(self, endpoint):
        ID_NAMES = ["id", "userid", "accountid", "orderid", "profileid"]
        for param in endpoint.parameters:
            if param.get("name", "").lower() in ID_NAMES:
                return True
        return "{" in endpoint.path and "}" in endpoint.path

    def run(self, endpoint, client, auth_contexts):
        pass


class MethodExposureCheck(BaseCheck):
    def applies_to(self, endpoint):
        return endpoint.method in {"GET", "POST"}

    def run(self, endpoint, client, auth_contexts):
        pass

class ErrorLeakCheck(BaseCheck):
    def applies_to(self, endpoint):
        return True

    def run(self, endpoint, client, auth_contexts):
        pass

class TokenLifeCycleCheck(BaseCheck):
    def applies_to(self, endpoint):
        path = endpoint.path.lower()
        return any(x in path for x in ["refresh", "logout", "token", "session", "auth"])

    def run(self, endpoint, client, auth_contexts):
        pass
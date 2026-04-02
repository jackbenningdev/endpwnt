import requests

class HttpClient:
    def __init__(
        self,
        base_url: str,
        timeout: int = 10,
        default_headers: dict[str, str] | None = None,
        verify_tls: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(default_headers or {})
        self.session.verify = verify_tls

    def send(self, endpoint, auth_context=None, params=None, json_body=None, data=None):
        url = f"{self.base_url}{endpoint.path}"

        headers = {}
        cookies = {}

        if auth_context:
            headers.update(auth_context.headers)
            cookies.update(auth_context.cookies)

        try:
            return self.session.request(
                method=endpoint.method,
                url=url,
                headers=headers,
                cookies=cookies,
                params=params,
                json=json_body,
                data=data,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException as e:
            print("Request failed: " + str(e))
            return None
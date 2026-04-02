import yaml

class Endpwnt:
    def __init__(self, filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                spec = yaml.safe_load(f)

            self.endpoints = []

            for path, methods in spec.get("paths", {}).items():
                for method, details in methods.items():
                    self.endpoints.append({
                        "method": method.upper(),
                        "path": path,
                        "summary": details.get("summary"),
                        "operationId": details.get("operationId"),
                    })

        except Exception as e:
            print("could not import openAPI")
        print(self.endpoints)


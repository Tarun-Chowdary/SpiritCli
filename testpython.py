import requests

response = requests.get(
    "https://api.bank.com/data",
    verify=False
)
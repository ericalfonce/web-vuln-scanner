import requests
from requests.exceptions import RequestException

def make_get_request(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except RequestException as e:
        print(f"Error making GET request to {url}: {e}")
        return None

def make_post_request(url, data):
    try:
        response = requests.post(url, json=data)
        response.raise_for_status()
        return response.json()
    except RequestException as e:
        print(f"Error making POST request to {url}: {e}")
        return None

def check_url_reachable(url):
    try:
        response = requests.head(url, allow_redirects=True)
        return response.status_code == 200
    except RequestException:
        return False
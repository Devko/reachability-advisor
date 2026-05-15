import requests


def reconcile(job):
    target = job["callback_url"]
    response = requests.get(target)
    return response.status_code

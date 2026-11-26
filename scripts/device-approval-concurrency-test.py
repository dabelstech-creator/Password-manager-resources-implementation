#!/usr/bin/env python3
"""Staging integration/concurrency checks for AuthPlatform device approval.

Required environment:
  AUTHPLATFORM_BASE_URL
  AUTHPLATFORM_OAUTH_CLIENT_ID
  AUTHPLATFORM_ACCESS_TOKEN   (valid WorkOS/AuthPlatform bearer token)
Optional:
  TELEGRAM_BOT_SHARED_SECRET and TELEGRAM_USER_ID (for Telegram service-auth checks)

This script creates disposable device grants; run only against a staging deployment.
"""
import concurrent.futures
import json
import os
import sys
import urllib.error
import urllib.request

BASE = os.environ["AUTHPLATFORM_BASE_URL"].rstrip("/")
CLIENT = os.environ["AUTHPLATFORM_OAUTH_CLIENT_ID"]
TOKEN = os.environ["AUTHPLATFORM_ACCESS_TOKEN"]


def request(path, method="GET", payload=None, headers=None):
    body = None if payload is None else json.dumps(payload).encode()
    h = {"Accept": "application/json"}
    if body is not None:
        h["Content-Type"] = "application/json"
    if headers:
        h.update(headers)
    req = urllib.request.Request(BASE + path, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            value = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            value = raw.decode(errors="replace")
        return error.code, value


def main():
    auth = {"Authorization": "Bearer " + TOKEN}
    status, grant = request("/oauth/device_authorization", "POST",
                             {"client_id": CLIENT, "scope": "devices:read"}, auth)
    assert status == 200, (status, grant)
    code, device_code = grant["user_code"], grant["device_code"]

    # Opposing decisions race on one pending grant. Exactly one state transition
    # must win; losing decisions must report 409 rather than overwrite the winner.
    decisions = [True, False] * 12
    def decide(value):
        return request("/device/approve", "POST",
                       {"user_code": code, "approve": value}, auth)[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(decide, decisions))
    assert 204 in results, ("no approval decision won", results)
    assert all(code in (204, 409) for code in results), results

    # Concurrent token polling must never issue more than one token for a grant.
    token_payload = {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                     "device_code": device_code, "client_id": CLIENT}
    def poll(_):
        return request("/oauth/token", "POST", token_payload)[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        token_results = list(pool.map(poll, range(12)))
    assert token_results.count(200) <= 1, token_results
    assert any(code in (200, 400) for code in token_results), token_results

    # Invalid service credentials must never pass Telegram device approval.
    secret = os.environ.get("TELEGRAM_BOT_SHARED_SECRET")
    telegram_id = os.environ.get("TELEGRAM_USER_ID")
    if secret and telegram_id:
        status, _ = request("/v1/telegram/device-approval", "POST",
            {"telegram_user_id": telegram_id, "user_code": code, "approve": True},
            {"X-AuthPlatform-Telegram-Secret": "invalid-test-secret"})
        assert status == 401, ("Telegram endpoint accepted an invalid service secret", status)

    print(json.dumps({"device_grant_created": True,
                      "approval_http_statuses": {str(s): results.count(s) for s in set(results)},
                      "token_poll_http_statuses": {str(s): token_results.count(s) for s in set(token_results)},
                      "max_tokens_issued": token_results.count(200),
                      "telegram_invalid_secret_rejected": bool(secret and telegram_id)}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("INTEGRATION TEST FAILED:", exc, file=sys.stderr)
        raise

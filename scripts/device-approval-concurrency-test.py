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
        return request("/oauth/token", "POST", token_payload)
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        token_results = list(pool.map(poll, range(12)))
    token_statuses = [status for status, _ in token_results]
    assert token_statuses.count(200) <= 1, token_statuses
    if token_statuses.count(200) == 0:
        assert any((body or {}).get("error") == "access_denied" for _, body in token_results), token_results

    # Exercise the authenticated Telegram path with a real linked test account.
    secret = os.environ.get("TELEGRAM_BOT_SHARED_SECRET")
    telegram_id = os.environ.get("TELEGRAM_USER_ID")
    telegram_approval_passed = False
    invalid_secret_rejected = False
    if secret and telegram_id:
        telegram_headers = {"X-AuthPlatform-Telegram-Secret": secret}
        status, telegram_grant = request("/oauth/device_authorization", "POST",
            {"client_id": CLIENT, "scope": "devices:read"}, auth)
        assert status == 200, (status, telegram_grant)
        telegram_code = telegram_grant["user_code"]
        preview_path = "/v1/telegram/device-authorizations?telegram_user_id=" + telegram_id + "&user_code=" + telegram_code
        status, preview = request(preview_path, headers=telegram_headers)
        assert status == 200 and preview["client_id"] == CLIENT, (status, preview)
        status, _ = request("/v1/telegram/device-approval", "POST",
            {"telegram_user_id": telegram_id, "user_code": telegram_code, "approve": True},
            {"X-AuthPlatform-Telegram-Secret": "invalid-test-secret"})
        assert status == 401, ("Telegram endpoint accepted an invalid service secret", status)
        invalid_secret_rejected = True
        status, _ = request("/v1/telegram/device-approval", "POST",
            {"telegram_user_id": telegram_id, "user_code": telegram_code, "approve": True},
            telegram_headers)
        assert status == 204, ("Telegram approval failed", status)
        status, token_response = request("/oauth/token", "POST",
            {"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
             "device_code": telegram_grant["device_code"], "client_id": CLIENT})
        assert status == 200 and token_response.get("access_token"), (status, token_response)
        telegram_approval_passed = True

    print(json.dumps({"device_grant_created": True,
                      "approval_http_statuses": {str(s): results.count(s) for s in set(results)},
                      "token_poll_http_statuses": {str(s): token_statuses.count(s) for s in set(token_statuses)},
                      "max_tokens_issued": token_statuses.count(200),
                      "telegram_valid_approval_passed": telegram_approval_passed,
                      "telegram_invalid_secret_rejected": invalid_secret_rejected}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("INTEGRATION TEST FAILED:", exc, file=sys.stderr)
        raise

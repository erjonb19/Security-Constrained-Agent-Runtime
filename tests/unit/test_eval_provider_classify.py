"""Unit tests for the eval harness's infrastructure-vs-regression classifier.

A provider outage (402/429/5xx/network/timeout) must be scored as an
infrastructure failure, NOT counted as an accuracy regression. These tests pin
that boundary so a billing lapse or rate limit never masquerades as the agent
getting dumber.
"""

from eval_harness import _is_provider_error


def _mk(name, message="", status_code=None):
    """Build a stand-in exception with a given class name and optional
    SDK-style ``status_code`` attribute, without depending on the openai SDK."""
    exc = type(name, (Exception,), {})(message)
    if status_code is not None:
        exc.status_code = status_code
    return exc


# --- infrastructure failures: must be provider errors ---------------------

def test_402_payment_required_is_provider_error():
    assert _is_provider_error(
        _mk("PermissionDeniedError", "Error code: 402 - payment required", 402))


def test_429_rate_limit_is_provider_error():
    assert _is_provider_error(_mk("RateLimitError", "rate limit exceeded", 429))


def test_5xx_is_provider_error():
    assert _is_provider_error(_mk("InternalServerError", "Error code: 503", 503))


def test_network_error_recognised_by_class_name():
    assert _is_provider_error(_mk("APIConnectionError", "connection error"))


def test_timeout_recognised_by_class_name():
    assert _is_provider_error(_mk("APITimeoutError", "request timed out"))


def test_message_only_fallback_when_no_status_code():
    assert _is_provider_error(Exception("Error code: 429 - Too Many Requests"))


def test_403_no_credits_is_provider_error():
    # xAI returns billing exhaustion as 403, not 402. A "no credits" failure is
    # an availability problem, not an accuracy regression.
    assert _is_provider_error(_mk(
        "PermissionDeniedError",
        "Error code: 403 - {'code': 'permission-denied', 'error': "
        "\"Your newly created team doesn't have any credits or licenses yet\"}",
        403))


# --- genuine failures: must NOT be provider errors ------------------------

def test_400_bad_request_is_not_provider_error():
    assert not _is_provider_error(
        _mk("BadRequestError", "invalid schema field", 400))


def test_plain_value_error_is_not_provider_error():
    assert not _is_provider_error(ValueError("could not parse generated SQL"))


def test_401_auth_error_is_not_infra_outage():
    # a missing/invalid key is a config problem, surfaced elsewhere -- not the
    # transient-outage signal the gate short-circuits on.
    assert not _is_provider_error(_mk("AuthenticationError", "invalid api key", 401))


def test_403_model_access_is_not_provider_error():
    # a bare permission/model-access 403 (no billing language) is a real config
    # bug to fix (e.g. wrong model id), so it must stay a hard failure, not warn.
    assert not _is_provider_error(_mk(
        "PermissionDeniedError",
        "Error code: 403 - you do not have access to model grok-9", 403))

import time

from hypothesis import given
from hypothesis import strategies as st

from ai_footprint.tokens import decode_jwt, flatten_claims, inspect_token, verify_rs256
from tests.conftest import FAKE_ANTHROPIC_ACCESS, jwks_for_test_key, make_jwt

NOW = 1_800_000_000


def test_anthropic_access_token_is_classified_as_opaque_with_expiry():
    info = inspect_token(
        "accessToken",
        FAKE_ANTHROPIC_ACCESS,
        now=NOW,
        expires_at=(NOW - 60) * 1000,
        scopes=["user:inference"],
    )
    assert info.kind == "anthropic_oauth_access"
    assert info.prefix == "sk-ant-oat01-…"
    assert info.expired is True
    assert info.scopes == ["user:inference"]
    assert "opaque" in info.signature


def test_jwt_claims_are_decoded_and_session_ids_dropped():
    token = make_jwt(
        {
            "iss": "https://issuer",
            "exp": NOW + 10,
            "sid": "secret-session",
            "scp": ["openid", "email"],
            "nested": {"plan": "pro"},
        }
    )
    info = inspect_token("access_token", token, now=NOW)
    assert info.kind == "jwt"
    assert info.issuer == "https://issuer"
    assert info.expired is False
    assert info.scopes == ["openid", "email"]
    assert info.claims["nested.plan"] == "pro"
    assert "sid" not in info.claims


def test_unknown_format_is_reported_as_opaque():
    assert inspect_token("x", "zzzzzzzzzzzzzzzzzzzzzzzz", now=NOW).kind == "opaque"


def test_malformed_jwt_is_not_decoded():
    assert decode_jwt("eyJ.not-base64!.x") is None
    assert decode_jwt("only.two") is None


def test_rs256_signature_verifies_against_matching_jwks():
    token = make_jwt({"iss": "https://issuer", "exp": int(time.time()) + 60})
    ok, why = verify_rs256(token, jwks_for_test_key())
    assert ok, why


def test_tampered_payload_fails_verification():
    token = make_jwt({"sub": "alice"})
    header, _payload, signature = token.split(".")
    forged = make_jwt({"sub": "mallory"}, sign=False).split(".")[1]
    ok, _why = verify_rs256(f"{header}.{forged}.{signature}", jwks_for_test_key())
    assert not ok


def test_unknown_key_id_fails_verification():
    ok, why = verify_rs256(make_jwt({"a": 1}, kid="other"), jwks_for_test_key())
    assert not ok
    assert "kid" in why


def test_flatten_truncates_long_values():
    flat = flatten_claims({"k": "v" * 500})
    assert len(flat["k"]) == 158


@given(
    st.text(alphabet=st.characters(min_codepoint=33, max_codepoint=126), min_size=24, max_size=200)
)
def test_metadata_never_contains_the_secret(secret: str):
    info = inspect_token("field", secret, now=NOW)
    assert secret not in repr(info)

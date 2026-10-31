"""Sandbox client id resolution and the non-interactive token guard.

No network: get_access_token never reaches a real endpoint in these tests,
and token storage is a pytest tmp_path.
"""
import json
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

import digikey.v3.ordering
from digikey.exceptions import DigikeyOauthException
from digikey.oauth import oauth2
from digikey.v3.api import DigikeyApiWrapper


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.setenv('DIGIKEY_STORAGE_PATH', str(tmp_path))
    monkeypatch.setenv('DIGIKEY_CLIENT_ID', 'prod-id')
    monkeypatch.setenv('DIGIKEY_CLIENT_SECRET', 'prod-secret')
    monkeypatch.delenv('DIGIKEY_SANDBOX_CLIENT_ID', raising=False)
    monkeypatch.delenv('DIGIKEY_SANDBOX_CLIENT_SECRET', raising=False)
    monkeypatch.delenv('DIGIKEY_NONINTERACTIVE', raising=False)
    return tmp_path


def _token(expires_in=3600):
    return {'access_token': 'at', 'refresh_token': 'rt', 'token_type': 'Bearer',
            'expires': (datetime.now(timezone.utc)
                        + timedelta(seconds=expires_in)).timestamp()}


# open_new raises in the noninteractive tests so a regression fails at once
# instead of sitting in the 5 minute HTTPServer loop.


def _wrapper(sandbox):
    with mock.patch.object(oauth2.TokenHandler, 'get_access_token',
                           return_value=oauth2.Oauth2Token(_token())):
        return DigikeyApiWrapper('order_with_http_info', digikey.v3.ordering,
                                 sandbox=sandbox)


def _api_key_header(wrapper):
    return wrapper._api_instance.api_client.configuration.api_key['X-DIGIKEY-Client-Id']


def test_sandbox_uses_sandbox_client_id_for_both_id_slots(env, monkeypatch):
    monkeypatch.setenv('DIGIKEY_SANDBOX_CLIENT_ID', 'sandbox-id')
    wrapper = _wrapper(sandbox=True)
    assert wrapper.x_digikey_client_id == 'sandbox-id'
    assert _api_key_header(wrapper) == 'sandbox-id'


def test_production_ignores_sandbox_client_id(env, monkeypatch):
    monkeypatch.setenv('DIGIKEY_SANDBOX_CLIENT_ID', 'sandbox-id')
    wrapper = _wrapper(sandbox=False)
    assert wrapper.x_digikey_client_id == 'prod-id'
    assert _api_key_header(wrapper) == 'prod-id'


def test_noninteractive_refuses_when_no_token_stored(env, monkeypatch):
    monkeypatch.setenv('DIGIKEY_NONINTERACTIVE', '1')
    with mock.patch.object(oauth2, 'open_new', side_effect=AssertionError('browser')):
        with pytest.raises(DigikeyOauthException):
            oauth2.TokenHandler(version=3).get_access_token()


def test_noninteractive_refuses_when_refresh_fails(env, monkeypatch):
    monkeypatch.setenv('DIGIKEY_NONINTERACTIVE', '1')
    (env / oauth2.TOKEN_STORAGE).write_text(json.dumps(_token(expires_in=-60)))
    with mock.patch.object(oauth2.TokenHandler, '_TokenHandler__refresh_token',
                           side_effect=DigikeyOauthException('dead')), \
            mock.patch.object(oauth2, 'open_new', side_effect=AssertionError('browser')):
        with pytest.raises(DigikeyOauthException):
            oauth2.TokenHandler(version=3).get_access_token()


def test_noninteractive_keeps_a_valid_token(env, monkeypatch):
    monkeypatch.setenv('DIGIKEY_NONINTERACTIVE', '1')
    (env / oauth2.TOKEN_STORAGE).write_text(json.dumps(_token()))
    assert oauth2.TokenHandler(version=3).get_access_token().access_token == 'at'


def test_interactive_flow_unchanged_without_the_flag(env):
    class Stop(Exception):
        pass

    with mock.patch.object(oauth2, 'open_new', side_effect=Stop) as browser:
        with pytest.raises(Stop):
            oauth2.TokenHandler(version=3).get_access_token()
    browser.assert_called_once()

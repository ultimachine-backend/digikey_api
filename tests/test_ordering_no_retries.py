"""POST /Orders places a real order, so urllib3 must never re-send it.

No network: the connection itself is faked, one level below urllib3's retry
loop, so the assertion counts what would really have gone out on the wire.
"""
from unittest import mock

import pytest
import urllib3

from digikey.v3.ordering.configuration import Configuration
from digikey.v3.ordering.rest import ApiException, RESTClientObject


def _client():
    configuration = Configuration()
    configuration.host = 'https://sandbox-api.digikey.com/Ordering/v3'
    return RESTClientObject(configuration)


@pytest.mark.parametrize('error', [
    urllib3.exceptions.SSLError('decryption failed or bad record mac'),
    urllib3.exceptions.ProtocolError('connection aborted'),
    urllib3.exceptions.NewConnectionError(mock.Mock(), 'refused'),
])
def test_order_post_is_sent_exactly_once(error):
    client = _client()
    with mock.patch(
            'urllib3.connectionpool.HTTPSConnectionPool._make_request',
            side_effect=error) as send:
        with pytest.raises((ApiException, urllib3.exceptions.HTTPError)):
            client.POST('https://sandbox-api.digikey.com/Ordering/v3/Orders',
                        headers={'Content-Type': 'application/json'},
                        body={'PurchaseOrderNumber': '1'})
    assert send.call_count == 1


def test_every_write_branch_disables_retries():
    client = _client()
    response = mock.Mock(status=200, data=b'{}')
    url = 'https://sandbox-api.digikey.com/Ordering/v3/Orders'
    with mock.patch.object(client.pool_manager, 'request',
                           return_value=response) as request:
        client.POST(url, headers={'Content-Type': 'application/json'}, body={})
        client.POST(url, post_params=[('a', '1')], headers={
            'Content-Type': 'application/x-www-form-urlencoded'})
        client.POST(url, post_params=[('a', '1')], headers={
            'Content-Type': 'multipart/form-data'})
        client.POST(url, body='raw', headers={'Content-Type': 'text/plain'})
    assert request.call_count == 4
    assert all(call.kwargs['retries'] is False
               for call in request.call_args_list)

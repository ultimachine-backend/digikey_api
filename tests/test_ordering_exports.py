"""Ordering client is exported and serializes to DigiKey's JSON shape."""
import digikey
from digikey.v3.ordering import OrderRequest, LineItem


def test_place_order_exported():
    assert callable(digikey.place_order)


def test_order_request_attribute_map():
    # Guards against regenerating the client with different field names.
    assert OrderRequest.attribute_map['purchase_order_number'] == 'PurchaseOrderNumber'
    assert OrderRequest.attribute_map['ship_method'] == 'ShipMethod'
    assert 'RequestedQuantity' in LineItem.attribute_map.values()


def test_ordering_api_exception_propagates():
    """call_api_function must NOT swallow ordering errors (place_order callers
    rely on catching digikey.v3.ordering.rest.ApiException themselves).

    The swallow guard in digikey/v3/api.py catches only
    digikey.v3.productinformation.rest.ApiException; the ordering client
    raises a distinct class. If that import is ever widened, place_order()
    would silently return None on API errors.
    """
    import pytest
    from digikey.v3.api import DigikeyApiWrapper
    from digikey.v3.ordering.rest import ApiException as OrderingApiException

    wrapper = DigikeyApiWrapper.__new__(DigikeyApiWrapper)
    wrapper.wrapped_function = 'boom'
    wrapper.authorization = 'auth'
    wrapper.x_digikey_client_id = 'cid'

    class FakeApi:
        def boom(self, *a, **k):
            raise OrderingApiException(status=400, reason='bad request')

    wrapper._api_instance = FakeApi()
    with pytest.raises(OrderingApiException):
        wrapper.call_api_function(body=object())

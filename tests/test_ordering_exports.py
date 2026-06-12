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

# coding: utf-8

"""
    Order Details

    Retrieve information about current and past orders.  # noqa: E501

    OpenAPI spec version: v3
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class BackOrderDetails(object):
    """NOTE: This class is auto generated by the swagger code generator program.

    Do not edit the class manually.
    """

    """
    Attributes:
      swagger_types (dict): The key is attribute name
                            and the value is attribute type.
      attribute_map (dict): The key is attribute name
                            and the value is json key in definition.
    """
    swagger_types = {
        'quantity': 'int',
        'back_order_estimates': 'list[Schedule]'
    }

    attribute_map = {
        'quantity': 'Quantity',
        'back_order_estimates': 'BackOrderEstimates'
    }

    def __init__(self, quantity=None, back_order_estimates=None):  # noqa: E501
        """BackOrderDetails - a model defined in Swagger"""  # noqa: E501

        self._quantity = None
        self._back_order_estimates = None
        self.discriminator = None

        if quantity is not None:
            self.quantity = quantity
        if back_order_estimates is not None:
            self.back_order_estimates = back_order_estimates

    @property
    def quantity(self):
        """Gets the quantity of this BackOrderDetails.  # noqa: E501

        The total quantity that is backorder. This quantity is the same as LinteItem.QuantityBackorder  # noqa: E501

        :return: The quantity of this BackOrderDetails.  # noqa: E501
        :rtype: int
        """
        return self._quantity

    @quantity.setter
    def quantity(self, quantity):
        """Sets the quantity of this BackOrderDetails.

        The total quantity that is backorder. This quantity is the same as LinteItem.QuantityBackorder  # noqa: E501

        :param quantity: The quantity of this BackOrderDetails.  # noqa: E501
        :type: int
        """

        self._quantity = quantity

    @property
    def back_order_estimates(self):
        """Gets the back_order_estimates of this BackOrderDetails.  # noqa: E501

        The Manufacturer's estimated date and quantity that Digi-Key will receive the product.  # noqa: E501

        :return: The back_order_estimates of this BackOrderDetails.  # noqa: E501
        :rtype: list[Schedule]
        """
        return self._back_order_estimates

    @back_order_estimates.setter
    def back_order_estimates(self, back_order_estimates):
        """Sets the back_order_estimates of this BackOrderDetails.

        The Manufacturer's estimated date and quantity that Digi-Key will receive the product.  # noqa: E501

        :param back_order_estimates: The back_order_estimates of this BackOrderDetails.  # noqa: E501
        :type: list[Schedule]
        """

        self._back_order_estimates = back_order_estimates

    def to_dict(self):
        """Returns the model properties as a dict"""
        result = {}

        for attr, _ in six.iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value
        if issubclass(BackOrderDetails, dict):
            for key, value in self.items():
                result[key] = value

        return result

    def to_str(self):
        """Returns the string representation of the model"""
        return pprint.pformat(self.to_dict())

    def __repr__(self):
        """For `print` and `pprint`"""
        return self.to_str()

    def __eq__(self, other):
        """Returns true if both objects are equal"""
        if not isinstance(other, BackOrderDetails):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

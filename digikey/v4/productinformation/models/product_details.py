# coding: utf-8

"""
    ProductSearch Api

    ProductSearch Api  # noqa: E501

    OpenAPI spec version: v4
    
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class ProductDetails(object):
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
        'search_locale_used': 'IsoSearchLocale',
        'product': 'Product'
    }

    attribute_map = {
        'search_locale_used': 'SearchLocaleUsed',
        'product': 'Product'
    }

    def __init__(self, search_locale_used=None, product=None):  # noqa: E501
        """ProductDetails - a model defined in Swagger"""  # noqa: E501

        self._search_locale_used = None
        self._product = None
        self.discriminator = None

        if search_locale_used is not None:
            self.search_locale_used = search_locale_used
        if product is not None:
            self.product = product

    @property
    def search_locale_used(self):
        """Gets the search_locale_used of this ProductDetails.  # noqa: E501


        :return: The search_locale_used of this ProductDetails.  # noqa: E501
        :rtype: IsoSearchLocale
        """
        return self._search_locale_used

    @search_locale_used.setter
    def search_locale_used(self, search_locale_used):
        """Sets the search_locale_used of this ProductDetails.


        :param search_locale_used: The search_locale_used of this ProductDetails.  # noqa: E501
        :type: IsoSearchLocale
        """

        self._search_locale_used = search_locale_used

    @property
    def product(self):
        """Gets the product of this ProductDetails.  # noqa: E501


        :return: The product of this ProductDetails.  # noqa: E501
        :rtype: Product
        """
        return self._product

    @product.setter
    def product(self, product):
        """Sets the product of this ProductDetails.


        :param product: The product of this ProductDetails.  # noqa: E501
        :type: Product
        """

        self._product = product

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
        if issubclass(ProductDetails, dict):
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
        if not isinstance(other, ProductDetails):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

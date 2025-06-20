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


class PriceSettingsUsed(object):
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
        'customer_id_used': 'int'
    }

    attribute_map = {
        'search_locale_used': 'SearchLocaleUsed',
        'customer_id_used': 'CustomerIdUsed'
    }

    def __init__(self, search_locale_used=None, customer_id_used=None):  # noqa: E501
        """PriceSettingsUsed - a model defined in Swagger"""  # noqa: E501

        self._search_locale_used = None
        self._customer_id_used = None
        self.discriminator = None

        if search_locale_used is not None:
            self.search_locale_used = search_locale_used
        if customer_id_used is not None:
            self.customer_id_used = customer_id_used

    @property
    def search_locale_used(self):
        """Gets the search_locale_used of this PriceSettingsUsed.  # noqa: E501


        :return: The search_locale_used of this PriceSettingsUsed.  # noqa: E501
        :rtype: IsoSearchLocale
        """
        return self._search_locale_used

    @search_locale_used.setter
    def search_locale_used(self, search_locale_used):
        """Sets the search_locale_used of this PriceSettingsUsed.


        :param search_locale_used: The search_locale_used of this PriceSettingsUsed.  # noqa: E501
        :type: IsoSearchLocale
        """

        self._search_locale_used = search_locale_used

    @property
    def customer_id_used(self):
        """Gets the customer_id_used of this PriceSettingsUsed.  # noqa: E501

        The CustomerId that was used for the search and pricing  # noqa: E501

        :return: The customer_id_used of this PriceSettingsUsed.  # noqa: E501
        :rtype: int
        """
        return self._customer_id_used

    @customer_id_used.setter
    def customer_id_used(self, customer_id_used):
        """Sets the customer_id_used of this PriceSettingsUsed.

        The CustomerId that was used for the search and pricing  # noqa: E501

        :param customer_id_used: The customer_id_used of this PriceSettingsUsed.  # noqa: E501
        :type: int
        """

        self._customer_id_used = customer_id_used

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
        if issubclass(PriceSettingsUsed, dict):
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
        if not isinstance(other, PriceSettingsUsed):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

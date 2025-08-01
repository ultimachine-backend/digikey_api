# coding: utf-8

"""
    Ordering Api

    Queues an order for processing.  # noqa: E501

    OpenAPI spec version: v3
    Contact: api.support@digikey.com
    Generated by: https://github.com/swagger-api/swagger-codegen.git
"""


import pprint
import re  # noqa: F401

import six


class Contact(object):
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
        'customer_id': 'str',
        'name': 'str',
        'address': 'Address',
        'telephone': 'str'
    }

    attribute_map = {
        'customer_id': 'CustomerId',
        'name': 'Name',
        'address': 'Address',
        'telephone': 'Telephone'
    }

    def __init__(self, customer_id=None, name=None, address=None, telephone=None):  # noqa: E501
        """Contact - a model defined in Swagger"""  # noqa: E501

        self._customer_id = None
        self._name = None
        self._address = None
        self._telephone = None
        self.discriminator = None

        if customer_id is not None:
            self.customer_id = customer_id
        if name is not None:
            self.name = name
        if address is not None:
            self.address = address
        if telephone is not None:
            self.telephone = telephone

    @property
    def customer_id(self):
        """Gets the customer_id of this Contact.  # noqa: E501

        Your Digi-Key customer id  # noqa: E501

        :return: The customer_id of this Contact.  # noqa: E501
        :rtype: str
        """
        return self._customer_id

    @customer_id.setter
    def customer_id(self, customer_id):
        """Sets the customer_id of this Contact.

        Your Digi-Key customer id  # noqa: E501

        :param customer_id: The customer_id of this Contact.  # noqa: E501
        :type: str
        """

        self._customer_id = customer_id

    @property
    def name(self):
        """Gets the name of this Contact.  # noqa: E501

        Customer's name  # noqa: E501

        :return: The name of this Contact.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this Contact.

        Customer's name  # noqa: E501

        :param name: The name of this Contact.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def address(self):
        """Gets the address of this Contact.  # noqa: E501


        :return: The address of this Contact.  # noqa: E501
        :rtype: Address
        """
        return self._address

    @address.setter
    def address(self, address):
        """Sets the address of this Contact.


        :param address: The address of this Contact.  # noqa: E501
        :type: Address
        """

        self._address = address

    @property
    def telephone(self):
        """Gets the telephone of this Contact.  # noqa: E501

        Contact's telephone number  # noqa: E501

        :return: The telephone of this Contact.  # noqa: E501
        :rtype: str
        """
        return self._telephone

    @telephone.setter
    def telephone(self, telephone):
        """Sets the telephone of this Contact.

        Contact's telephone number  # noqa: E501

        :param telephone: The telephone of this Contact.  # noqa: E501
        :type: str
        """

        self._telephone = telephone

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
        if issubclass(Contact, dict):
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
        if not isinstance(other, Contact):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

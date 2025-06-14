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


class CategoryType(object):
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
        'category_id': 'int',
        'level': 'int',
        'name': 'str'
    }

    attribute_map = {
        'category_id': 'CategoryId',
        'level': 'Level',
        'name': 'Name'
    }

    def __init__(self, category_id=None, level=None, name=None):  # noqa: E501
        """CategoryType - a model defined in Swagger"""  # noqa: E501

        self._category_id = None
        self._level = None
        self._name = None
        self.discriminator = None

        if category_id is not None:
            self.category_id = category_id
        if level is not None:
            self.level = level
        if name is not None:
            self.name = name

    @property
    def category_id(self):
        """Gets the category_id of this CategoryType.  # noqa: E501

        ID for DigiKey product category  # noqa: E501

        :return: The category_id of this CategoryType.  # noqa: E501
        :rtype: int
        """
        return self._category_id

    @category_id.setter
    def category_id(self, category_id):
        """Sets the category_id of this CategoryType.

        ID for DigiKey product category  # noqa: E501

        :param category_id: The category_id of this CategoryType.  # noqa: E501
        :type: int
        """

        self._category_id = category_id

    @property
    def level(self):
        """Gets the level of this CategoryType.  # noqa: E501

        DigiKey Product Category level  # noqa: E501

        :return: The level of this CategoryType.  # noqa: E501
        :rtype: int
        """
        return self._level

    @level.setter
    def level(self, level):
        """Sets the level of this CategoryType.

        DigiKey Product Category level  # noqa: E501

        :param level: The level of this CategoryType.  # noqa: E501
        :type: int
        """

        self._level = level

    @property
    def name(self):
        """Gets the name of this CategoryType.  # noqa: E501

        Name of DigiKey product category  # noqa: E501

        :return: The name of this CategoryType.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this CategoryType.

        Name of DigiKey product category  # noqa: E501

        :param name: The name of this CategoryType.  # noqa: E501
        :type: str
        """

        self._name = name

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
        if issubclass(CategoryType, dict):
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
        if not isinstance(other, CategoryType):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

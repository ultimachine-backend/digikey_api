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


class ParameterValue(object):
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
        'parameter_id': 'int',
        'parameter_text': 'str',
        'parameter_type': 'str',
        'value_id': 'str',
        'value_text': 'str'
    }

    attribute_map = {
        'parameter_id': 'ParameterId',
        'parameter_text': 'ParameterText',
        'parameter_type': 'ParameterType',
        'value_id': 'ValueId',
        'value_text': 'ValueText'
    }

    def __init__(self, parameter_id=None, parameter_text=None, parameter_type=None, value_id=None, value_text=None):  # noqa: E501
        """ParameterValue - a model defined in Swagger"""  # noqa: E501

        self._parameter_id = None
        self._parameter_text = None
        self._parameter_type = None
        self._value_id = None
        self._value_text = None
        self.discriminator = None

        if parameter_id is not None:
            self.parameter_id = parameter_id
        if parameter_text is not None:
            self.parameter_text = parameter_text
        if parameter_type is not None:
            self.parameter_type = parameter_type
        if value_id is not None:
            self.value_id = value_id
        if value_text is not None:
            self.value_text = value_text

    @property
    def parameter_id(self):
        """Gets the parameter_id of this ParameterValue.  # noqa: E501

        Parameter Id  # noqa: E501

        :return: The parameter_id of this ParameterValue.  # noqa: E501
        :rtype: int
        """
        return self._parameter_id

    @parameter_id.setter
    def parameter_id(self, parameter_id):
        """Sets the parameter_id of this ParameterValue.

        Parameter Id  # noqa: E501

        :param parameter_id: The parameter_id of this ParameterValue.  # noqa: E501
        :type: int
        """

        self._parameter_id = parameter_id

    @property
    def parameter_text(self):
        """Gets the parameter_text of this ParameterValue.  # noqa: E501

        Parameter Text  # noqa: E501

        :return: The parameter_text of this ParameterValue.  # noqa: E501
        :rtype: str
        """
        return self._parameter_text

    @parameter_text.setter
    def parameter_text(self, parameter_text):
        """Sets the parameter_text of this ParameterValue.

        Parameter Text  # noqa: E501

        :param parameter_text: The parameter_text of this ParameterValue.  # noqa: E501
        :type: str
        """

        self._parameter_text = parameter_text

    @property
    def parameter_type(self):
        """Gets the parameter_type of this ParameterValue.  # noqa: E501

        Parameter Data Type  # noqa: E501

        :return: The parameter_type of this ParameterValue.  # noqa: E501
        :rtype: str
        """
        return self._parameter_type

    @parameter_type.setter
    def parameter_type(self, parameter_type):
        """Sets the parameter_type of this ParameterValue.

        Parameter Data Type  # noqa: E501

        :param parameter_type: The parameter_type of this ParameterValue.  # noqa: E501
        :type: str
        """
        allowed_values = ["String", "Integer", "Double", "UnitOfMeasure", "CoupledUnitOfMeasure", "RangeUnitOfMeasure"]  # noqa: E501
        if parameter_type not in allowed_values:
            raise ValueError(
                "Invalid value for `parameter_type` ({0}), must be one of {1}"  # noqa: E501
                .format(parameter_type, allowed_values)
            )

        self._parameter_type = parameter_type

    @property
    def value_id(self):
        """Gets the value_id of this ParameterValue.  # noqa: E501

        The Id of the Parameter value  # noqa: E501

        :return: The value_id of this ParameterValue.  # noqa: E501
        :rtype: str
        """
        return self._value_id

    @value_id.setter
    def value_id(self, value_id):
        """Sets the value_id of this ParameterValue.

        The Id of the Parameter value  # noqa: E501

        :param value_id: The value_id of this ParameterValue.  # noqa: E501
        :type: str
        """

        self._value_id = value_id

    @property
    def value_text(self):
        """Gets the value_text of this ParameterValue.  # noqa: E501

        The text of the Parameter value  # noqa: E501

        :return: The value_text of this ParameterValue.  # noqa: E501
        :rtype: str
        """
        return self._value_text

    @value_text.setter
    def value_text(self, value_text):
        """Sets the value_text of this ParameterValue.

        The text of the Parameter value  # noqa: E501

        :param value_text: The value_text of this ParameterValue.  # noqa: E501
        :type: str
        """

        self._value_text = value_text

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
        if issubclass(ParameterValue, dict):
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
        if not isinstance(other, ParameterValue):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

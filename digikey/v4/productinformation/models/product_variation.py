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


class ProductVariation(object):
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
        'digi_key_product_number': 'str',
        'package_type': 'PackageType',
        'standard_pricing': 'list[PriceBreak]',
        'my_pricing': 'list[PriceBreak]',
        'market_place': 'bool',
        'tariff_active': 'bool',
        'supplier': 'Supplier',
        'quantity_availablefor_package_type': 'int',
        'max_quantity_for_distribution': 'int',
        'minimum_order_quantity': 'int',
        'standard_package': 'int',
        'digi_reel_fee': 'float'
    }

    attribute_map = {
        'digi_key_product_number': 'DigiKeyProductNumber',
        'package_type': 'PackageType',
        'standard_pricing': 'StandardPricing',
        'my_pricing': 'MyPricing',
        'market_place': 'MarketPlace',
        'tariff_active': 'TariffActive',
        'supplier': 'Supplier',
        'quantity_availablefor_package_type': 'QuantityAvailableforPackageType',
        'max_quantity_for_distribution': 'MaxQuantityForDistribution',
        'minimum_order_quantity': 'MinimumOrderQuantity',
        'standard_package': 'StandardPackage',
        'digi_reel_fee': 'DigiReelFee'
    }

    def __init__(self, digi_key_product_number=None, package_type=None, standard_pricing=None, my_pricing=None, market_place=None, tariff_active=None, supplier=None, quantity_availablefor_package_type=None, max_quantity_for_distribution=None, minimum_order_quantity=None, standard_package=None, digi_reel_fee=None):  # noqa: E501
        """ProductVariation - a model defined in Swagger"""  # noqa: E501

        self._digi_key_product_number = None
        self._package_type = None
        self._standard_pricing = None
        self._my_pricing = None
        self._market_place = None
        self._tariff_active = None
        self._supplier = None
        self._quantity_availablefor_package_type = None
        self._max_quantity_for_distribution = None
        self._minimum_order_quantity = None
        self._standard_package = None
        self._digi_reel_fee = None
        self.discriminator = None

        if digi_key_product_number is not None:
            self.digi_key_product_number = digi_key_product_number
        if package_type is not None:
            self.package_type = package_type
        if standard_pricing is not None:
            self.standard_pricing = standard_pricing
        if my_pricing is not None:
            self.my_pricing = my_pricing
        if market_place is not None:
            self.market_place = market_place
        if tariff_active is not None:
            self.tariff_active = tariff_active
        if supplier is not None:
            self.supplier = supplier
        if quantity_availablefor_package_type is not None:
            self.quantity_availablefor_package_type = quantity_availablefor_package_type
        if max_quantity_for_distribution is not None:
            self.max_quantity_for_distribution = max_quantity_for_distribution
        if minimum_order_quantity is not None:
            self.minimum_order_quantity = minimum_order_quantity
        if standard_package is not None:
            self.standard_package = standard_package
        if digi_reel_fee is not None:
            self.digi_reel_fee = digi_reel_fee

    @property
    def digi_key_product_number(self):
        """Gets the digi_key_product_number of this ProductVariation.  # noqa: E501

        DigiKey Product number of the variation  # noqa: E501

        :return: The digi_key_product_number of this ProductVariation.  # noqa: E501
        :rtype: str
        """
        return self._digi_key_product_number

    @digi_key_product_number.setter
    def digi_key_product_number(self, digi_key_product_number):
        """Sets the digi_key_product_number of this ProductVariation.

        DigiKey Product number of the variation  # noqa: E501

        :param digi_key_product_number: The digi_key_product_number of this ProductVariation.  # noqa: E501
        :type: str
        """

        self._digi_key_product_number = digi_key_product_number

    @property
    def package_type(self):
        """Gets the package_type of this ProductVariation.  # noqa: E501


        :return: The package_type of this ProductVariation.  # noqa: E501
        :rtype: PackageType
        """
        return self._package_type

    @package_type.setter
    def package_type(self, package_type):
        """Sets the package_type of this ProductVariation.


        :param package_type: The package_type of this ProductVariation.  # noqa: E501
        :type: PackageType
        """

        self._package_type = package_type

    @property
    def standard_pricing(self):
        """Gets the standard_pricing of this ProductVariation.  # noqa: E501

        Standard pricing for the validated locale.  # noqa: E501

        :return: The standard_pricing of this ProductVariation.  # noqa: E501
        :rtype: list[PriceBreak]
        """
        return self._standard_pricing

    @standard_pricing.setter
    def standard_pricing(self, standard_pricing):
        """Sets the standard_pricing of this ProductVariation.

        Standard pricing for the validated locale.  # noqa: E501

        :param standard_pricing: The standard_pricing of this ProductVariation.  # noqa: E501
        :type: list[PriceBreak]
        """

        self._standard_pricing = standard_pricing

    @property
    def my_pricing(self):
        """Gets the my_pricing of this ProductVariation.  # noqa: E501

        Your pricing for the account with which you authenticated. Also dependent on locale information.  # noqa: E501

        :return: The my_pricing of this ProductVariation.  # noqa: E501
        :rtype: list[PriceBreak]
        """
        return self._my_pricing

    @my_pricing.setter
    def my_pricing(self, my_pricing):
        """Sets the my_pricing of this ProductVariation.

        Your pricing for the account with which you authenticated. Also dependent on locale information.  # noqa: E501

        :param my_pricing: The my_pricing of this ProductVariation.  # noqa: E501
        :type: list[PriceBreak]
        """

        self._my_pricing = my_pricing

    @property
    def market_place(self):
        """Gets the market_place of this ProductVariation.  # noqa: E501

        Product is a Marketplace product that ships direct from the supplier. A separate shipping fee may apply  # noqa: E501

        :return: The market_place of this ProductVariation.  # noqa: E501
        :rtype: bool
        """
        return self._market_place

    @market_place.setter
    def market_place(self, market_place):
        """Sets the market_place of this ProductVariation.

        Product is a Marketplace product that ships direct from the supplier. A separate shipping fee may apply  # noqa: E501

        :param market_place: The market_place of this ProductVariation.  # noqa: E501
        :type: bool
        """

        self._market_place = market_place

    @property
    def tariff_active(self):
        """Gets the tariff_active of this ProductVariation.  # noqa: E501

        Indicates if there is a tariff on the item.  # noqa: E501

        :return: The tariff_active of this ProductVariation.  # noqa: E501
        :rtype: bool
        """
        return self._tariff_active

    @tariff_active.setter
    def tariff_active(self, tariff_active):
        """Sets the tariff_active of this ProductVariation.

        Indicates if there is a tariff on the item.  # noqa: E501

        :param tariff_active: The tariff_active of this ProductVariation.  # noqa: E501
        :type: bool
        """

        self._tariff_active = tariff_active

    @property
    def supplier(self):
        """Gets the supplier of this ProductVariation.  # noqa: E501


        :return: The supplier of this ProductVariation.  # noqa: E501
        :rtype: Supplier
        """
        return self._supplier

    @supplier.setter
    def supplier(self, supplier):
        """Sets the supplier of this ProductVariation.


        :param supplier: The supplier of this ProductVariation.  # noqa: E501
        :type: Supplier
        """

        self._supplier = supplier

    @property
    def quantity_availablefor_package_type(self):
        """Gets the quantity_availablefor_package_type of this ProductVariation.  # noqa: E501

        The quantity available for the specified variation.  # noqa: E501

        :return: The quantity_availablefor_package_type of this ProductVariation.  # noqa: E501
        :rtype: int
        """
        return self._quantity_availablefor_package_type

    @quantity_availablefor_package_type.setter
    def quantity_availablefor_package_type(self, quantity_availablefor_package_type):
        """Sets the quantity_availablefor_package_type of this ProductVariation.

        The quantity available for the specified variation.  # noqa: E501

        :param quantity_availablefor_package_type: The quantity_availablefor_package_type of this ProductVariation.  # noqa: E501
        :type: int
        """

        self._quantity_availablefor_package_type = quantity_availablefor_package_type

    @property
    def max_quantity_for_distribution(self):
        """Gets the max_quantity_for_distribution of this ProductVariation.  # noqa: E501

        Maximum order quantity for Distribution  # noqa: E501

        :return: The max_quantity_for_distribution of this ProductVariation.  # noqa: E501
        :rtype: int
        """
        return self._max_quantity_for_distribution

    @max_quantity_for_distribution.setter
    def max_quantity_for_distribution(self, max_quantity_for_distribution):
        """Sets the max_quantity_for_distribution of this ProductVariation.

        Maximum order quantity for Distribution  # noqa: E501

        :param max_quantity_for_distribution: The max_quantity_for_distribution of this ProductVariation.  # noqa: E501
        :type: int
        """

        self._max_quantity_for_distribution = max_quantity_for_distribution

    @property
    def minimum_order_quantity(self):
        """Gets the minimum_order_quantity of this ProductVariation.  # noqa: E501

        The Minimum Order Quantity  # noqa: E501

        :return: The minimum_order_quantity of this ProductVariation.  # noqa: E501
        :rtype: int
        """
        return self._minimum_order_quantity

    @minimum_order_quantity.setter
    def minimum_order_quantity(self, minimum_order_quantity):
        """Sets the minimum_order_quantity of this ProductVariation.

        The Minimum Order Quantity  # noqa: E501

        :param minimum_order_quantity: The minimum_order_quantity of this ProductVariation.  # noqa: E501
        :type: int
        """

        self._minimum_order_quantity = minimum_order_quantity

    @property
    def standard_package(self):
        """Gets the standard_package of this ProductVariation.  # noqa: E501

        The number of products in the manufacturer's standard package.  # noqa: E501

        :return: The standard_package of this ProductVariation.  # noqa: E501
        :rtype: int
        """
        return self._standard_package

    @standard_package.setter
    def standard_package(self, standard_package):
        """Sets the standard_package of this ProductVariation.

        The number of products in the manufacturer's standard package.  # noqa: E501

        :param standard_package: The standard_package of this ProductVariation.  # noqa: E501
        :type: int
        """

        self._standard_package = standard_package

    @property
    def digi_reel_fee(self):
        """Gets the digi_reel_fee of this ProductVariation.  # noqa: E501

        Fee per reel ordered.  # noqa: E501

        :return: The digi_reel_fee of this ProductVariation.  # noqa: E501
        :rtype: float
        """
        return self._digi_reel_fee

    @digi_reel_fee.setter
    def digi_reel_fee(self, digi_reel_fee):
        """Sets the digi_reel_fee of this ProductVariation.

        Fee per reel ordered.  # noqa: E501

        :param digi_reel_fee: The digi_reel_fee of this ProductVariation.  # noqa: E501
        :type: float
        """

        self._digi_reel_fee = digi_reel_fee

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
        if issubclass(ProductVariation, dict):
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
        if not isinstance(other, ProductVariation):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

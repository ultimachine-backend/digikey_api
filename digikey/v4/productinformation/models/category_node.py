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


class CategoryNode(object):
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
        'parent_id': 'int',
        'name': 'str',
        'product_count': 'int',
        'new_product_count': 'int',
        'image_url': 'str',
        'seo_description': 'str',
        'child_categories': 'list[CategoryNode]'
    }

    attribute_map = {
        'category_id': 'CategoryId',
        'parent_id': 'ParentId',
        'name': 'Name',
        'product_count': 'ProductCount',
        'new_product_count': 'NewProductCount',
        'image_url': 'ImageUrl',
        'seo_description': 'SeoDescription',
        'child_categories': 'ChildCategories'
    }

    def __init__(self, category_id=None, parent_id=None, name=None, product_count=None, new_product_count=None, image_url=None, seo_description=None, child_categories=None):  # noqa: E501
        """CategoryNode - a model defined in Swagger"""  # noqa: E501

        self._category_id = None
        self._parent_id = None
        self._name = None
        self._product_count = None
        self._new_product_count = None
        self._image_url = None
        self._seo_description = None
        self._child_categories = None
        self.discriminator = None

        if category_id is not None:
            self.category_id = category_id
        if parent_id is not None:
            self.parent_id = parent_id
        if name is not None:
            self.name = name
        if product_count is not None:
            self.product_count = product_count
        if new_product_count is not None:
            self.new_product_count = new_product_count
        if image_url is not None:
            self.image_url = image_url
        if seo_description is not None:
            self.seo_description = seo_description
        if child_categories is not None:
            self.child_categories = child_categories

    @property
    def category_id(self):
        """Gets the category_id of this CategoryNode.  # noqa: E501

        The Category Id  # noqa: E501

        :return: The category_id of this CategoryNode.  # noqa: E501
        :rtype: int
        """
        return self._category_id

    @category_id.setter
    def category_id(self, category_id):
        """Sets the category_id of this CategoryNode.

        The Category Id  # noqa: E501

        :param category_id: The category_id of this CategoryNode.  # noqa: E501
        :type: int
        """

        self._category_id = category_id

    @property
    def parent_id(self):
        """Gets the parent_id of this CategoryNode.  # noqa: E501

        If this is a child category, this is the Id of the parent category  # noqa: E501

        :return: The parent_id of this CategoryNode.  # noqa: E501
        :rtype: int
        """
        return self._parent_id

    @parent_id.setter
    def parent_id(self, parent_id):
        """Sets the parent_id of this CategoryNode.

        If this is a child category, this is the Id of the parent category  # noqa: E501

        :param parent_id: The parent_id of this CategoryNode.  # noqa: E501
        :type: int
        """

        self._parent_id = parent_id

    @property
    def name(self):
        """Gets the name of this CategoryNode.  # noqa: E501

        Category name  # noqa: E501

        :return: The name of this CategoryNode.  # noqa: E501
        :rtype: str
        """
        return self._name

    @name.setter
    def name(self, name):
        """Sets the name of this CategoryNode.

        Category name  # noqa: E501

        :param name: The name of this CategoryNode.  # noqa: E501
        :type: str
        """

        self._name = name

    @property
    def product_count(self):
        """Gets the product_count of this CategoryNode.  # noqa: E501

        The number of products in the category  # noqa: E501

        :return: The product_count of this CategoryNode.  # noqa: E501
        :rtype: int
        """
        return self._product_count

    @product_count.setter
    def product_count(self, product_count):
        """Sets the product_count of this CategoryNode.

        The number of products in the category  # noqa: E501

        :param product_count: The product_count of this CategoryNode.  # noqa: E501
        :type: int
        """

        self._product_count = product_count

    @property
    def new_product_count(self):
        """Gets the new_product_count of this CategoryNode.  # noqa: E501

        The number of new products in the category  # noqa: E501

        :return: The new_product_count of this CategoryNode.  # noqa: E501
        :rtype: int
        """
        return self._new_product_count

    @new_product_count.setter
    def new_product_count(self, new_product_count):
        """Sets the new_product_count of this CategoryNode.

        The number of new products in the category  # noqa: E501

        :param new_product_count: The new_product_count of this CategoryNode.  # noqa: E501
        :type: int
        """

        self._new_product_count = new_product_count

    @property
    def image_url(self):
        """Gets the image_url of this CategoryNode.  # noqa: E501

        The URL of the image of the category  # noqa: E501

        :return: The image_url of this CategoryNode.  # noqa: E501
        :rtype: str
        """
        return self._image_url

    @image_url.setter
    def image_url(self, image_url):
        """Sets the image_url of this CategoryNode.

        The URL of the image of the category  # noqa: E501

        :param image_url: The image_url of this CategoryNode.  # noqa: E501
        :type: str
        """

        self._image_url = image_url

    @property
    def seo_description(self):
        """Gets the seo_description of this CategoryNode.  # noqa: E501

        The SEO description for the category  # noqa: E501

        :return: The seo_description of this CategoryNode.  # noqa: E501
        :rtype: str
        """
        return self._seo_description

    @seo_description.setter
    def seo_description(self, seo_description):
        """Sets the seo_description of this CategoryNode.

        The SEO description for the category  # noqa: E501

        :param seo_description: The seo_description of this CategoryNode.  # noqa: E501
        :type: str
        """

        self._seo_description = seo_description

    @property
    def child_categories(self):
        """Gets the child_categories of this CategoryNode.  # noqa: E501

        A list of all children of the category - Their parent Id will be Category Id  # noqa: E501

        :return: The child_categories of this CategoryNode.  # noqa: E501
        :rtype: list[CategoryNode]
        """
        return self._child_categories

    @child_categories.setter
    def child_categories(self, child_categories):
        """Sets the child_categories of this CategoryNode.

        A list of all children of the category - Their parent Id will be Category Id  # noqa: E501

        :param child_categories: The child_categories of this CategoryNode.  # noqa: E501
        :type: list[CategoryNode]
        """

        self._child_categories = child_categories

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
        if issubclass(CategoryNode, dict):
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
        if not isinstance(other, CategoryNode):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """Returns true if both objects are not equal"""
        return not self == other

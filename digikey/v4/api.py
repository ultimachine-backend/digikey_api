import os
import logging
from distutils.util import strtobool
import digikey.oauth.oauth2
from digikey.exceptions import DigikeyError
from digikey.v4.productinformation import (KeywordRequest, KeywordResponse, ProductDetails, DigiReelPricing)
from digikey.v4.productinformation.rest import ApiException

logger = logging.getLogger(__name__)


class DigikeyApiV4Wrapper(object):
    def __init__(self, wrapped_function, module):
        self.sandbox = False

        # V4 API configuration
        apinames = {
            digikey.v4.productinformation: 'products',
        }

        apiclasses = {
            digikey.v4.productinformation: digikey.v4.productinformation.ProductSearchApi,
        }

        apiname = apinames[module]
        apiclass = apiclasses[module]

        # Configure API key authorization: apiKeySecurity
        configuration = module.Configuration()
        configuration.api_key['X-DIGIKEY-Client-Id'] = os.getenv('DIGIKEY_CLIENT_ID')

        # Return quietly if no clientid has been set to prevent errors when importing the module
        if os.getenv('DIGIKEY_CLIENT_ID') is None or os.getenv('DIGIKEY_CLIENT_SECRET') is None:
            raise DigikeyError('Please provide a valid DIGIKEY_CLIENT_ID and DIGIKEY_CLIENT_SECRET in your env setup')

        # Configure OAuth2 access token for authorization: oauth2AccessCodeSecurity
        # Use v3 OAuth system (same OAuth for both versions)
        self._digikeyApiToken = digikey.oauth.oauth2.TokenHandler(version=4, sandbox=self.sandbox).get_access_token()
        configuration.access_token = self._digikeyApiToken.access_token

        # Explicitly set the Authorization header
        if not hasattr(configuration, 'default_headers'):
            configuration.default_headers = {}

        configuration.default_headers['Authorization'] = f'Bearer {self._digikeyApiToken.access_token}'

        # V4 API endpoint - check what the generated API expects
        configuration.host = 'https://api.digikey.com/products/v4'
        
        # Use sandbox API if configured
        try:
            if bool(strtobool(os.getenv('DIGIKEY_CLIENT_SANDBOX'))):
                configuration.host = 'https://sandbox-api.digikey.com/products/v4'
                self.sandbox = True
        except (ValueError, AttributeError):
            pass

        # create an instance of the API class
        self._api_instance = apiclass(module.ApiClient(configuration))

        # Populate reused ids
        self.x_digikey_client_id = os.getenv('DIGIKEY_CLIENT_ID')
        self.wrapped_function = wrapped_function

    def call_api_function(self, *args, **kwargs):
        try:
            # If optional api_limits, status mutable object is passed use it to store API limits and status code
            api_limits = kwargs.pop('api_limits', None)
            status = kwargs.pop('status', None)

            func = getattr(self._api_instance, self.wrapped_function)
            logger.debug(f'CALL wrapped v4 -> {func.__qualname__}')
            
            # V4 API signature: (self, x_digikey_client_id, **kwargs)
            # Authorization token is handled through configuration.access_token
            api_response = func(*args, self.x_digikey_client_id, **kwargs)
            
            self._remaining_requests(api_response[2], api_limits)
            self._store_api_statuscode(api_response[1], status)

            return api_response[0]
        except ApiException as e:
            logger.error(f'Exception when calling v4 {self.wrapped_function}: {e}')
            self._store_api_statuscode(e.status, status)
            raise  # Re-raise the exception so caller can handle it


    @staticmethod
    def _remaining_requests(header, api_limits):
        try:
            rate_limit = header['X-RateLimit-Limit']
            rate_limit_rem = header['X-RateLimit-Remaining']

            if api_limits is not None and type(api_limits) == dict:
                api_limits['api_requests_limit'] = int(rate_limit)
                api_limits['api_requests_remaining'] = int(rate_limit_rem)

            logger.debug('Requests remaining: [{}/{}]'.format(rate_limit_rem, rate_limit))
        except (KeyError, ValueError) as e:
            logger.debug(f'No api limits returned -> {e.__class__.__name__}: {e}')
            if api_limits is not None and type(api_limits) == dict:
                api_limits['api_requests_limit'] = None
                api_limits['api_requests_remaining'] = None

    @staticmethod
    def _store_api_statuscode(statuscode, status):
        if status is not None and type(status) == dict:
            status['code'] = int(statuscode)

        logger.debug('API returned code: {}'.format(statuscode))


# V4 API Functions
def keyword_search(*args, **kwargs) -> KeywordResponse:
    client = DigikeyApiV4Wrapper('keyword_search_with_http_info', digikey.v4.productinformation)

    if 'body' in kwargs and type(kwargs['body']) == KeywordRequest:
        logger.info(f'V4 Search for: {kwargs["body"].keywords}')
        logger.debug('CALL -> keyword_search v4')
        return client.call_api_function(*args, **kwargs)
    else:
        raise DigikeyError('Please provide a valid KeywordSearchRequest argument')


def product_details(*args, **kwargs) -> ProductDetails:
    client = DigikeyApiV4Wrapper('product_details_with_http_info', digikey.v4.productinformation)

    if len(args):
        logger.info(f'V4 Get product details for: {args[0]}')
        return client.call_api_function(*args, **kwargs)


def digi_reel_pricing(*args, **kwargs) -> DigiReelPricing:
    client = DigikeyApiV4Wrapper('digi_reel_pricing_with_http_info', digikey.v4.productinformation)

    if len(args):
        logger.info(f'V4 Calculate the DigiReel pricing for {args[0]} with quantity {args[1]}')
        return client.call_api_function(*args, **kwargs)


def suggested_parts(*args, **kwargs) -> ProductDetails:
    client = DigikeyApiV4Wrapper('suggested_parts_with_http_info', digikey.v4.productinformation)

    if len(args):
        logger.info(f'V4 Retrieve detailed product information and two suggested products for: {args[0]}')
        return client.call_api_function(*args, **kwargs)


# Add any new V4-specific functions here
def product_associations(*args, **kwargs):
    """V4-specific function for product associations"""
    client = DigikeyApiV4Wrapper('product_associations_with_http_info', digikey.v4.productinformation)
    
    if len(args):
        logger.info(f'V4 Get product associations for: {args[0]}')
        return client.call_api_function(*args, **kwargs)


def product_pricing(*args, **kwargs):
    """V4-specific function for product pricing"""
    client = DigikeyApiV4Wrapper('product_pricing_with_http_info', digikey.v4.productinformation)
    
    if len(args):
        logger.info(f'V4 Get product pricing for: {args[0]}')
        return client.call_api_function(*args, **kwargs)

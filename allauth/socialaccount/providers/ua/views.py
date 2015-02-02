import json
import requests
from requests_oauthlib import OAuth1

from django.utils.translation import gettext as _

from allauth.socialaccount.providers.oauth.client import OAuth, OAuthError, get_token_prefix
from allauth.socialaccount.providers.oauth.views import (OAuthAdapter,
                                                         OAuthLoginView,
                                                         OAuthCallbackView)

from .provider import UaProvider


class UaAPI(OAuth):
    url = 'http://identity.ua.pt/oauth/get_data'

    # Override the method to directly append oauth_version
    def query(self, url, method="GET", params=dict(), headers=dict()):
        """
        Request a API endpoint at ``url`` with ``params`` being either the
        POST or GET data.
        """
        access_token = self._get_at_from_session()
        oauth = OAuth1(
            self.consumer_key,
            client_secret=self.secret_key,
            resource_owner_key=access_token['oauth_token'],
            resource_owner_secret=access_token['oauth_token_secret'],
            signature_type='query',
            oauth_version='1.0a')
        response = getattr(requests, method.lower())(url,
                                                     auth=oauth,
                                                     headers=headers,
                                                     params=params)

        if response.status_code != 200:
            raise OAuthError(
                _('No access to private resources at "%s".')
                % get_token_prefix(self.request_token_url))

        return response.text

    def get_user_info(self):
        response1 = self.query(self.url, params={'scope': 'uu', 'format': 'json'})
        response2 = self.query(self.url, params={'scope': 'name', 'format': 'json'})

        email = json.loads(response1)['email']
        obj = json.loads(response2)
        name = '%s %s' % (obj['name'], obj['surname'])
        user = {
            'uu': email,
            'firstname': obj['name'],
            'surname': obj['surname'],
            'name': name
        }

        return user


class UaOAuthAdapter(OAuthAdapter):
    provider_id = UaProvider.id
    request_token_url = 'http://identity.ua.pt/oauth/request_token'
    access_token_url = 'http://identity.ua.pt/oauth/access_token'
    authorize_url = 'http://identity.ua.pt/oauth/authorize'

    def complete_login(self, request, app, token):
        client = UaAPI(request, app.client_id, app.secret,
                       self.request_token_url)
        extra_data = client.get_user_info()
        return self.get_provider().sociallogin_from_response(request, extra_data)


oauth_login = OAuthLoginView.adapter_view(UaOAuthAdapter)
oauth_callback = OAuthCallbackView.adapter_view(UaOAuthAdapter)

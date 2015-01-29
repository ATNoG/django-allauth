from allauth.socialaccount import providers
from allauth.socialaccount.providers.base import (ProviderAccount, AuthAction)
from allauth.socialaccount.providers.oauth.provider import OAuthProvider


class UaAccount(ProviderAccount):
    def get_screen_name(self):
        return self.account.extra_data.get('name')

    def to_str(self):
        screen_name = self.get_screen_name()
        return screen_name or super(UaAccount, self).to_str()


class UaProvider(OAuthProvider):
    id = 'ua'
    name = 'UA'
    package = 'allauth.socialaccount.providers.ua'
    account_class = UaAccount

    def get_auth_url(self, request, action):
        return 'http://identity.ua.pt/oauth/authorize'

    def extract_uid(self, data):
        return data['uu']

    def extract_common_fields(self, data):
        return dict(username=data.get('name'), email=data.get('uu'), name=data.get('name'))


providers.registry.register(UaProvider)

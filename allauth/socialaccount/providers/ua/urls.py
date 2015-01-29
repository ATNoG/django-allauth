from allauth.socialaccount.providers.oauth.urls import default_urlpatterns

from .provider import UaProvider

urlpatterns = default_urlpatterns(UaProvider)
from django.urls import include, path

urlpatterns = [
    path("", include("shop.urls")),
    path("api/", include("shop.api_urls")),
]

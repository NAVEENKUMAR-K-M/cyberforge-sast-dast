from django.urls import path

from . import views

urlpatterns = [
    path("orders/", views.api_orders),
    path("orders/<int:pk>/", views.api_order),
    path("orders/new/", views.api_order_create),
]

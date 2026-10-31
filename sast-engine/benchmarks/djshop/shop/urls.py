from django.urls import path, re_path

from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("search/", views.search),
    path("products/<int:pk>/", views.product),
    path("products/<int:pk>/reviews/", views.ReviewView.as_view()),
    path("products/by-category/<str:category>/", views.by_category),
    path("products/named/<str:name>/", views.by_name),
    re_path(r"^archive/(?P<year>[0-9]{4})/$", views.archive),
    path("tools/ping/", views.ping),
    path("tools/dns/", views.dns),
    path("download/", views.download),
    path("report/", views.report),
    path("go/", views.go),
    path("welcome/", views.welcome),
    path("profile/", views.profile),
    path("contact/", views.contact),
    path("notes/", views.NoteList.as_view()),
    path("notes/new/", views.NoteCreate.as_view()),
]

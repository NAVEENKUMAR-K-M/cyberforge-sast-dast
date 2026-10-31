"""Django: urls.py and include() chains, function and class views, the ORM, forms and templates."""
import textwrap

from conftest import open_findings, safe_findings


def project(files):
    return {name: textwrap.dedent(body) for name, body in files.items()}


URLS = {
    "config/settings.py": 'ROOT_URLCONF = "config.urls"\nSECRET_KEY = "x"\n',
    "config/urls.py": """
        from django.urls import include, path
        urlpatterns = [
            path("shop/", include("shop.urls")),
            path("api/", include("shop.api")),
        ]
    """,
    "shop/urls.py": """
        from django.urls import path, re_path
        from . import views
        urlpatterns = [
            path("", views.home),
            path("search/", views.search, name="search"),
            path("items/<int:pk>/", views.item),
            path("by-name/<str:name>/", views.by_name),
            re_path(r"^archive/(?P<year>[0-9]{4})/$", views.archive),
            re_path(r"^old/(?P<slug>[\\w-]+)/$", views.old),
            path("reviews/<int:pk>/", views.ReviewView.as_view()),
        ]
    """,
    "shop/api.py": """
        from django.urls import path
        from django.views.decorators.http import require_POST
        from . import views
        urlpatterns = [path("orders/", views.api_orders), path("make/", require_POST(views.make))]
    """,
}

VIEWS = """
    from django.http import HttpResponse, JsonResponse
    from django.shortcuts import render, redirect
    from django.views import View
    from django.views.decorators.http import require_POST
    from django.db import connection

    def home(request):
        return HttpResponse("hi")

    def search(request):
        q = request.GET.get("q", "")
        with connection.cursor() as c:
            c.execute("SELECT * FROM shop_item WHERE name LIKE '%" + q + "%'")
        return HttpResponse("<h1>" + q + "</h1>")

    def item(request, pk):
        with connection.cursor() as c:
            c.execute("SELECT * FROM shop_item WHERE id = " + str(pk))
        return HttpResponse("ok")

    def by_name(request, name):
        with connection.cursor() as c:
            c.execute("SELECT * FROM shop_item WHERE name = '" + name + "'")
        return HttpResponse("ok")

    def archive(request, year):
        return HttpResponse(year)

    def old(request, slug):
        return HttpResponse("<p>" + slug + "</p>")

    def api_orders(request):
        return JsonResponse({"q": request.GET["customer"]})

    @require_POST
    def make(request):
        return redirect(request.POST.get("next"))

    class ReviewView(View):
        def get(self, request, pk):
            return HttpResponse("<p>" + request.GET.get("sort", "") + "</p>")
        def post(self, request, pk):
            return HttpResponse(self.kwargs["pk"])
"""


def scan_django(py_scan, **extra):
    files = project({**URLS, "shop/views.py": VIEWS, "shop/__init__.py": ""})
    files.update(project(extra))
    return py_scan(files)


def test_include_chains_prefixes_and_converters(py_scan):
    result = scan_django(py_scan)
    paths = {r["path"]: r["methods"] for r in result["routes"]}
    assert set(paths) == {
        "/shop/", "/shop/search/", "/shop/items/{pk}/", "/shop/by-name/{name}/", "/shop/archive/{year}/",
        "/shop/old/{slug}/", "/shop/reviews/{pk}/", "/api/orders/", "/api/make/"}
    assert paths["/api/make/"] == ["POST"]                  # require_POST around the view
    assert paths["/shop/reviews/{pk}/"] == ["GET", "POST"]  # the methods the class defines


def test_request_inputs_become_route_parameters(py_scan):
    result = scan_django(py_scan)
    params = {r["path"]: {(p["name"], p["location"]) for p in r["params"]} for r in result["routes"]}
    assert ("q", "query") in params["/shop/search/"]
    assert ("customer", "query") in params["/api/orders/"]
    assert ("next", "body") in params["/api/make/"]
    assert ("sort", "query") in params["/shop/reviews/{pk}/"] and ("pk", "path") in params["/shop/reviews/{pk}/"]


def test_converters_decide_which_path_values_can_carry_text(py_scan):
    result = scan_django(py_scan)
    sql = {f["routes"][0]["path"] for f in open_findings(result, 89)}
    assert sql == {"/shop/search/", "/shop/by-name/{name}/"}     # <int:pk> only ever holds digits
    assert any(f["routes"] and f["routes"][0]["path"] == "/shop/items/{pk}/" for f in safe_findings(result, 89))
    xss = {f["routes"][0]["path"] for f in open_findings(result, 79)}
    assert {"/shop/search/", "/shop/reviews/{pk}/"} <= xss
    assert "/shop/old/{slug}/" not in xss                         # [\w-]+ cannot hold markup
    typed = {p["name"]: p.get("type") for r in result["routes"] for p in r["params"] if r["path"] == "/shop/items/{pk}/"}
    assert typed == {"pk": "validated"}


def test_a_redirect_target_from_a_post_and_json_responses(py_scan):
    result = scan_django(py_scan)
    assert [f["routes"][0]["path"] for f in open_findings(result, 601)] == ["/api/make/"]
    assert not [f for f in open_findings(result, 79) if f["routes"] and f["routes"][0]["path"] == "/api/orders/"]


def test_models_forms_and_templates(py_scan):
    result = py_scan(project({
        "config/urls.py": "from django.urls import path\nfrom shop import views\nurlpatterns = [path('r/', views.reviews), path('c/', views.contact)]\n",
        "shop/__init__.py": "",
        "shop/models.py": """
            from django.db import models
            class Review(models.Model):
                body = models.TextField()
                stars = models.IntegerField()
        """,
        "shop/forms.py": """
            from django import forms
            class ContactForm(forms.Form):
                name = forms.CharField()
                age = forms.IntegerField()
        """,
        "shop/views.py": """
            from django.http import HttpResponse
            from django.shortcuts import render
            from .models import Review
            from .forms import ContactForm

            def reviews(request):
                if request.method == "POST":
                    Review.objects.create(body=request.POST["body"], stars=1)
                return render(request, "shop/reviews.html", {"reviews": Review.objects.all(), "title": request.GET.get("t", "")})

            def contact(request):
                form = ContactForm(request.POST)
                if form.is_valid():
                    return HttpResponse(f"<p>{form.cleaned_data['name']} is {form.cleaned_data['age']}</p>")
                return HttpResponse("form")
        """,
        "shop/templates/shop/reviews.html": "<h1>{{ title }}</h1>{% for r in reviews %}<li>{{ r.body|safe }}</li>{% endfor %}",
    }))
    stored = [f for f in open_findings(result, 79) if f["stored_flow"]]
    assert len(stored) == 1 and stored[0]["stored_flow"]["store"] == "orm:Review"
    assert [r["path"] for r in stored[0]["stored_flow"]["write_routes"]] == ["/r/"]
    # the escaped {{ title }} is not a finding, and the integer form field is not text
    form_xss = [f for f in open_findings(result, 79) if f["routes"] and f["routes"][0]["path"] == "/c/"]
    assert [p["name"] for f in form_xss for p in f["source_params"]] == ["name"]
    params = {p["name"] for r in result["routes"] if r["path"] == "/c/" for p in r["params"]}
    assert params == {"name", "age"}


def test_mark_safe_text_reaches_the_page(py_scan):
    result = py_scan(project({
        "config/urls.py": "from django.urls import path\nfrom shop import views\nurlpatterns = [path('m/', views.m)]\n",
        "shop/__init__.py": "",
        "shop/views.py": """
            from django.shortcuts import render
            from django.utils.safestring import mark_safe
            def m(request):
                return render(request, "m.html", {"note": mark_safe(request.GET["note"]), "plain": request.GET["plain"]})
        """,
        "templates/m.html": "<p>{{ note }}</p><p>{{ plain }}</p>",
    }))
    assert [p["name"] for f in open_findings(result, 79) for p in f["source_params"]] == ["note"]


def test_drf_routers_and_api_view(py_scan):
    result = py_scan(project({
        "config/urls.py": """
            from django.urls import include, path
            from rest_framework.routers import DefaultRouter
            from shop import views
            router = DefaultRouter()
            router.register(r"orders", views.OrderViewSet, basename="order")
            urlpatterns = [path("api/", include(router.urls)), path("ping/", views.ping)]
        """,
        "shop/__init__.py": "",
        "shop/views.py": """
            import subprocess
            from rest_framework.decorators import api_view
            from rest_framework.response import Response
            from django.db import connection

            class OrderViewSet:
                def list(self, request):
                    with connection.cursor() as c:
                        c.execute("SELECT * FROM o WHERE c = '" + request.query_params["customer"] + "'")
                    return Response([])
                def retrieve(self, request, pk=None):
                    return Response({})

            @api_view(["POST"])
            def ping(request):
                subprocess.run("ping " + request.data["host"], shell=True)
                return Response({})
        """,
    }))
    paths = {r["path"]: r["methods"] for r in result["routes"]}
    assert paths == {"/api/orders/": ["GET"], "/api/orders/{pk}/": ["GET"], "/ping/": ["POST"]}
    assert [f["routes"][0]["path"] for f in open_findings(result, 89)] == ["/api/orders/"]
    command = open_findings(result, 78)
    assert [f["routes"][0]["path"] for f in command] == ["/ping/"] and command[0]["source_params"][0]["name"] == "host"


def test_test_files_are_not_the_app(py_scan):
    result = py_scan(project({
        "shop/__init__.py": "",
        "shop/tests.py": 'PASSWORD = "Tr0ub4dor&3xyz"\n',
        "shop/test_views.py": 'API_SECRET = "Tr0ub4dor&3xyz"\n',
        "shop/settings.py": 'SECRET_KEY = "django-insecure-7f3a9c21d84b5e60aa"\n',
    }), semgrep=True)
    assert [f["file"] for f in open_findings(result, 798)] == ["shop/settings.py"]


# ---- generic class-based views --------------------------------------------------------------------------------------

GENERIC = {
    "config/urls.py": """
        from django.urls import path
        from shop import views
        urlpatterns = [
            path("reviews/", views.ReviewList.as_view()),
            path("reviews/new/", views.ReviewCreate.as_view()),
            path("reviews/<int:pk>/", views.ReviewDetail.as_view()),
            path("reviews/<int:pk>/edit/", views.ReviewUpdate.as_view()),
            path("reviews/<int:pk>/delete/", views.ReviewDelete.as_view()),
            path("contact/", views.Contact.as_view()),
            path("about/", views.About.as_view()),
        ]
    """,
    "shop/__init__.py": "",
    "shop/models.py": """
        from django.db import models
        class Review(models.Model):
            body = models.TextField()
            title = models.CharField(max_length=50)
            stars = models.IntegerField()
    """,
    "shop/forms.py": """
        from django import forms
        class ContactForm(forms.Form):
            name = forms.CharField()
            topic = forms.ChoiceField(choices=[("a", "A")])
    """,
    "shop/views.py": """
        from django.http import HttpResponse
        from django.views.generic import CreateView, DeleteView, DetailView, FormView, ListView, TemplateView, UpdateView
        from django.db import connection
        from .forms import ContactForm
        from .models import Review

        class ReviewList(ListView):
            model = Review
            paginate_by = 10
            template_name = "shop/review_list.html"

            def get_queryset(self):
                with connection.cursor() as c:
                    c.execute("SELECT * FROM shop_review WHERE title = '" + self.request.GET.get("t", "") + "'")
                return Review.objects.all()

        class ReviewCreate(CreateView):
            model = Review
            fields = ["body", "title", "stars"]
            success_url = "/reviews/"

        class ReviewDetail(DetailView):
            model = Review

        class ReviewUpdate(UpdateView):
            model = Review
            fields = "__all__"

        class ReviewDelete(DeleteView):
            model = Review
            success_url = "/reviews/"

        class Contact(FormView):
            form_class = ContactForm
            template_name = "shop/contact.html"

            def form_valid(self, form):
                return HttpResponse("<p>Thanks " + form.cleaned_data["name"] + " about " + form.cleaned_data["topic"] + "</p>")

        class About(TemplateView):
            template_name = "shop/about.html"
    """,
    "shop/templates/shop/review_list.html": "{% for r in object_list %}<li>{{ r.title }}: {{ r.body|safe }}</li>{% endfor %}",
}


def scan_generic(py_scan):
    return py_scan(project(GENERIC))


def test_generic_views_get_their_urls_methods_and_inputs(py_scan):
    result = scan_generic(py_scan)
    by_path = {r["path"]: r for r in result["routes"]}
    assert set(by_path) == {"/reviews/", "/reviews/new/", "/reviews/{pk}/", "/reviews/{pk}/edit/", "/reviews/{pk}/delete/",
                            "/contact/", "/about/"}
    assert by_path["/reviews/new/"]["methods"] == ["GET", "POST"] and by_path["/about/"]["methods"] == ["GET"]
    assert by_path["/reviews/{pk}/delete/"]["methods"] == ["DELETE", "GET", "POST"]

    def inputs(path):
        return {(p["name"], p["location"]): p.get("type") for p in by_path[path]["params"]}
    assert inputs("/reviews/new/") == {("body", "body"): None, ("title", "body"): None, ("stars", "body"): "validated"}
    assert inputs("/reviews/{pk}/edit/") == {("pk", "path"): "validated", ("body", "body"): None, ("title", "body"): None,
                                              ("stars", "body"): "validated"}
    assert ("page", "query") in inputs("/reviews/")                    # paginate_by reads ?page=
    assert ("t", "query") in inputs("/reviews/")                       # and the overridden get_queryset reads ?t=
    assert inputs("/contact/") == {("name", "body"): None, ("topic", "body"): "validated"}  # form_valid(form) reads cleaned_data


def test_hooks_the_framework_calls_are_analysed_with_the_requests_input(py_scan):
    result = scan_generic(py_scan)
    sql = open_findings(result, 89)
    assert [(f["routes"][0]["path"], f["source_params"][0]["name"]) for f in sql] == [("/reviews/", "t")]
    xss = [f for f in open_findings(result, 79) if f["routes"][0]["path"] == "/contact/"]
    assert [p["name"] for f in xss for p in f["source_params"]] == ["name"]   # the ChoiceField topic cannot carry markup


def test_a_createview_store_reaches_a_listview_template(py_scan):
    result = scan_generic(py_scan)
    stored = [f for f in open_findings(result, 79) if f["stored_flow"]]
    assert len(stored) == 1 and stored[0]["routes"][0]["path"] == "/reviews/"
    assert stored[0]["stored_flow"]["store"] == "orm:Review"
    writers = {r["path"] for r in stored[0]["stored_flow"]["write_routes"]}
    assert writers == {"/reviews/new/", "/reviews/{pk}/edit/"}
    assert {p["name"] for p in stored[0]["source_params"]} >= {"body"}  # the title is escaped by the template, the body is not

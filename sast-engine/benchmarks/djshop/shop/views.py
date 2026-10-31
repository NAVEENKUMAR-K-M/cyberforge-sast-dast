import json
import os
import subprocess

from django.conf import settings
from django.db import connection
from django.http import FileResponse, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils.html import escape
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from .forms import ContactForm
from .models import Note, Order, Product, Review

ALLOWED_NEXT = ("/", "/search/", "/profile/")


def home(request):
    return render(request, "shop/home.html")


def search(request):
    q = request.GET.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, name, price FROM shop_product WHERE name LIKE '%" + q + "%'")
        rows = cursor.fetchall()
    return render(request, "shop/search.html", {"q": q, "rows": rows})


def product(request, pk):
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, name, price FROM shop_product WHERE id = " + str(pk))
        row = cursor.fetchone()
    reviews = Review.objects.filter(product_id=pk)
    return render(request, "shop/product.html", {"product": row, "reviews": reviews, "pk": pk})


class ReviewView(View):
    def post(self, request, pk):
        Review.objects.create(product_id=pk, body=request.POST["body"])
        return redirect("/products/" + str(pk) + "/")


def by_category(request, category):
    rows = Product.objects.raw("SELECT * FROM shop_product WHERE category = '%s'" % category)
    return JsonResponse([{"id": p.id, "name": p.name} for p in rows], safe=False)


def by_name(request, name):
    rows = Product.objects.filter(name=name)
    return JsonResponse([{"id": p.id, "name": p.name} for p in rows], safe=False)


def archive(request, year):
    return HttpResponse("Archive " + year)


def ping(request):
    out = None
    if request.method == "POST":
        out = subprocess.run("ping -c 1 -W 1 " + request.POST["host"] + " 2>&1", shell=True, capture_output=True, text=True).stdout
    return render(request, "shop/ping.html", {"out": out})


def dns(request):
    done = subprocess.run(["nslookup", request.GET.get("host", "")], capture_output=True, text=True, timeout=10)
    return HttpResponse("<pre>" + escape(done.stdout) + "</pre>")


def download(request):
    path = os.path.join(settings.BASE_DIR, "shop", "files", request.GET["file"])
    return FileResponse(open(path, "rb"))


def report(request):
    name = os.path.basename(request.GET.get("name", ""))
    return FileResponse(open(os.path.join(settings.BASE_DIR, "shop", "files", name), "rb"))


def go(request):
    return redirect(request.GET.get("url", "/"))


def welcome(request):
    target = request.GET.get("to", "/")
    if target not in ALLOWED_NEXT:
        target = "/"
    return redirect(target)


def profile(request):
    return HttpResponse("<p>Hello " + escape(request.GET.get("name", "guest")) + "</p>")


def contact(request):
    if request.method == "POST":
        form = ContactForm(request.POST)
        if form.is_valid():
            return HttpResponse(f"<p>Thanks {form.cleaned_data['name']}, age {form.cleaned_data['age']}</p>")
    return render(request, "shop/contact.html")


def api_orders(request):
    customer = request.GET.get("customer", "")
    rows = Order.objects.raw("SELECT * FROM shop_order WHERE customer = '%s'" % customer)
    return JsonResponse([{"id": o.id, "customer": o.customer, "item": o.item} for o in rows], safe=False)


def api_order(request, pk):
    rows = Order.objects.filter(pk=pk)
    return JsonResponse([{"id": o.id, "item": o.item} for o in rows], safe=False)


@csrf_exempt
def api_order_create(request):
    data = json.loads(request.body)
    Order.objects.create(customer=data["customer"], item=data["item"])
    return JsonResponse({"status": "created"}, status=201)


from django.views.generic import CreateView, ListView  # noqa: E402


class NoteList(ListView):
    model = Note
    template_name = "shop/note_list.html"


class NoteCreate(CreateView):
    model = Note
    fields = ["text"]
    success_url = "/notes/"
    template_name = "shop/note_form.html"

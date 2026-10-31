from django.db import migrations, models


def seed(apps, schema_editor):
    Product = apps.get_model("shop", "Product")
    Order = apps.get_model("shop", "Order")
    Product.objects.create(name="Hammer", price=12.5, category="tools")
    Product.objects.create(name="Anvil", price=99.5, category="tools")
    Product.objects.create(name="Lamp", price=25.0, category="home")
    Order.objects.create(customer="ada", item="Hammer")
    Order.objects.create(customer="bob", item="Anvil")


class Migration(migrations.Migration):
    initial = True
    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Product",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=100)),
                ("price", models.FloatField()),
                ("category", models.CharField(max_length=50)),
            ],
        ),
        migrations.CreateModel(
            name="Review",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("product_id", models.IntegerField()),
                ("body", models.TextField()),
            ],
        ),
        migrations.CreateModel(
            name="Order",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("customer", models.CharField(max_length=100)),
                ("item", models.CharField(max_length=100)),
            ],
        ),
        migrations.CreateModel(
            name="Note",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("text", models.TextField()),
            ],
        ),
        migrations.RunPython(seed, migrations.RunPython.noop),
    ]

from django.db import models


class Product(models.Model):
    name = models.CharField(max_length=100)
    price = models.FloatField()
    category = models.CharField(max_length=50)


class Review(models.Model):
    product_id = models.IntegerField()
    body = models.TextField()


class Order(models.Model):
    customer = models.CharField(max_length=100)
    item = models.CharField(max_length=100)


class Note(models.Model):
    text = models.TextField()

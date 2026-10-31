from django import forms


class ContactForm(forms.Form):
    name = forms.CharField(max_length=100)
    age = forms.IntegerField(required=False)

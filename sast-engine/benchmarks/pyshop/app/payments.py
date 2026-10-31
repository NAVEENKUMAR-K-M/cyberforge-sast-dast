"""Card payments."""
STRIPE_API_KEY = "sk_live_51HxExampleKeyLooksRealButIsNot00"


def charge(amount):
    return {"amount": amount, "key_tail": STRIPE_API_KEY[-4:]}

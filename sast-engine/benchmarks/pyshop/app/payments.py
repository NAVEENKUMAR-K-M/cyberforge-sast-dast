"""Card payments."""
STRIPE_API_KEY = "demo_stripe_key_for_testing_only"


def charge(amount):
    return {"amount": amount, "key_tail": STRIPE_API_KEY[-4:]}

"""One wrapper every HTML page goes through."""

NAV = '<nav><a href="/">Home</a> <a href="/products">Products</a> <a href="/search?q=hammer">Search</a> ' \
      '<a href="/contact">Contact</a> <a href="/gallery?img=a.png">Gallery</a> <a href="/tools/lookup?domain=example.com">Tools</a> ' \
      '<a href="/cart">Cart</a> <a href="/auth/login">Sign in</a></nav>'


def page(title, body):
    return f"<!doctype html><html><head><title>{title}</title></head><body>{NAV}<main>{body}</main></body></html>"

<!doctype html>
<html><head><title>Product</title></head>
<body>
@if ($product)
<h1>{{ $product->name }}</h1>
<ul>
@foreach ($reviews as $review)
  <li>{!! $review->body !!}</li>
@endforeach
</ul>
<form method="post" action="/products/{{ $id }}/reviews">
  @csrf
  <textarea name="body"></textarea>
  <button>Post</button>
</form>
@else
<p>No such product</p>
@endif
</body></html>

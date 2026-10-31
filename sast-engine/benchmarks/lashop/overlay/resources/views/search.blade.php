<!doctype html>
<html><head><title>Search</title></head>
<body>
<form method="get" action="/search"><input name="q" value="hammer"><button>Go</button></form>
<h2>Results for {!! $q !!}</h2>
<ul>
@foreach ($rows as $row)
  <li>{{ $row->name }} - {{ $row->price }}</li>
@endforeach
</ul>
</body></html>

<!doctype html>
<html><head><title>Ping</title></head>
<body>
<form method="post" action="/tools/ping">
  @csrf
  <input name="host" value="127.0.0.1">
  <button>Ping</button>
</form>
@if ($out !== null)
<pre>{{ $out }}</pre>
@endif
</body></html>

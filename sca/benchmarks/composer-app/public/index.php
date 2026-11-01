<?php
// Builds a Symfony Request from the incoming PSR-7 request through symfony/psr-http-message-bridge.
// The app never touches HeaderUtils itself: the bridge's HttpFoundationFactory::createRequest() runs
// new Request(), whose HeaderBag parses Cache-Control with HeaderUtils::split(). In
// symfony/http-foundation v7.4.18 that function is GHSA-r925-mgvr-h9cc (ReDoS).
require __DIR__ . '/../vendor/autoload.php';

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;

$psr17 = new Psr17Factory();
$creator = new ServerRequestCreator($psr17, $psr17, $psr17, $psr17);
$psrRequest = $creator->fromGlobals();

$factory = new HttpFoundationFactory();
$request = $factory->createRequest($psrRequest);

header('Content-Type: text/plain');
echo 'Hello ', htmlspecialchars((string) $request->query->get('name', 'world'));

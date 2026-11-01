<?php
// Parses a posted YAML document with a Parser method the request chooses. Which method runs is only
// known at runtime: the default reaches Parser::parse() and from there lexInlineStructure()
// (GHSA-2v3c-qxhr-7vpv in symfony/yaml v7.4.17), but a static analysis can't resolve $parser->$action().
require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Yaml\Parser;

$parser = new Parser();
$action = $_GET['mode'] ?? 'parse';
$data = $parser->$action($_POST['document'] ?? '');

header('Content-Type: application/json');
echo json_encode($data);

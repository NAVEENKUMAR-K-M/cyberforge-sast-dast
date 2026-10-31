<?php
$format = $_GET['format'] ?? 'png';
passthru("file --mime-type input." . $format);

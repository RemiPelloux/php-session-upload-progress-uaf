<?php
// Minimal endpoint. It does nothing interesting on purpose: the bug lives in
// PHP's request startup, before this file is ever compiled.
header('Content-Type: text/plain');
echo "ok php=", PHP_VERSION,
     " status=", session_status(),
     " npost=", count($_POST),
     " peak=", memory_get_peak_usage(true), "\n";

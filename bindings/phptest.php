<?php
if (!extension_loaded('mscphplogparser')) {
    echo 'skip';
}
?>
<?php

//var_dump(LOG_TYPE_APACHE);
//var_dump(LOG_TYPE_NGINX);

//var_dump(LOGMSG_UNKNOWN);
//var_dump(LOGMSG_WARNING);
//var_dump(LOGMSG_ACCDENIED);
//var_dump(LOGMSG_REQBODY);
//var_dump(LOGMSG_ERROR);
//var_dump(LOGMSG_AUDITLOG);

///var_dump(LIBRARY_VERSION);
///var_dump(MODULE_VERSION);

if (count($argv) < 3) {
    echo "Argument missing!\n";
    exit;
}

$logtype = NULL;
if ($argv[2] == "apache") {
    //$logtype = LOG_TYPE_APACHE;
$logtype = 0;
}
elseif ($argv[2] == "nginx") {
    $logtype = LOG_TYPE_NGINX;
}
else {
    printf("Invalid logtype\n");
    exit;
}

$li = 1;
$fp = fopen($argv[1], "r");
if ($fp) {
    while (($line = fgets($fp)) !== false) {
        $len = strlen($line);
        echo json_encode(parse($line, $len, $logtype)) . "\n";
        $li++;
    }
    fclose($fp);
}
else {
    echo "Can't open file!\n";
    exit;
}

?>

<?php
require('smartfilter.class.php');

$key = 'key goes here';
$whitelist = 'whitelist goes here';
$input = 'the <script>alert("quick brown fox");</script> jumps over the lazy dog';

$smartfilter = new SmartFilter($key);

try {
  // Verify (returns a boolean)
  var_dump($smartfilter->verify());
  // Info (returns an associative array with the goodies)
  var_dump($smartfilter->info());
  // Verify whitelist (returns a boolean)
  var_dump($smartfilter->verify_whitelist($whitelist));
  // Detect (returns an associative array with the goodies)
  var_dump($smartfilter->detect($input, $whitelist));
  // Filter (returns an associative array with the goodies)
  var_dump($smartfilter->filter($input, $whitelist));
}
catch(SmartFilterNetworkException $e) {
    echo "Network connectivity issue\n";
}
catch(SmartFilterBadInputParameter $e) {
    echo "Bad input parameter exception\n";
}
catch(SmartFilterBadAPIKey $e) {
    echo "Bad API key\n";
}
catch(SmartFilterRequestTooLarge $e) {
    echo "Request too large\n";
}
catch(SmartFilterInternalError $e) {
    echo "Internal Prevoty error\n";
}
catch(SmartFilterAccountQuotaExceeded $e) {
    echo "Account quota exceeded\n";
}
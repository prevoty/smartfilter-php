<?php
require('smartfilter.class.php');

$api_key = 'api key goes here';
$rule_key = 'rule key goes here';
$input = 'the <script>alert("quick brown fox");</script> jumps over the lazy dog & mouse';

$smartfilter = new SmartFilter($api_key);

try {
  // Verify (returns a boolean)
  var_dump($smartfilter->verify());
  // Info (returns an associative array with the goodies)
  var_dump($smartfilter->info());
  // Verify rule (returns a boolean)
  var_dump($smartfilter->verify_rule($rule_key));
  // Filter (returns an associative array with the goodies)
  var_dump($smartfilter->filter($input, $rule_key));
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
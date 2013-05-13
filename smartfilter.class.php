<?php
require_once('lib/Requests.php');
Requests::register_autoloader();

class SmartFilterNetworkException extends Exception { }
class SmartFilterBadInputParameter extends Exception { }
class SmartFilterBadAPIKey extends Exception { }
class SmartFilterRequestTooLarge extends Exception { }
class SmartFilterInternalError extends Exception { }
class SmartFilterAccountQuotaExceeded extends Exception { }

class SmartFilter {
    private $key, $base;
    
    function __construct($key) {
        $this->key = $key;
        $this->base = 'http://api.prevoty.com/1';
    }

    // Endpoint: /key/verify
    function verify() {
        try {
            $response = Requests::get(
                $this->base . '/key/verify?api_key=' . $this->key, 
                array('Accept' => 'application/json')
            );
        }
        catch (Requests_Exception $e) {
            throw new SmartFilterNetworkException($e);
        }
        if ($response->status_code == 200) { return true; }
        if ($response->status_code == 400) { throw new SmartFilterBadInputParameter(); }
        if ($response->status_code == 403) { throw new SmartFilterBadAPIKey(); }
        if ($response->status_code == 500) { throw new SmartFilterInternalError(); }
        return false;
    }

    // Endpoint: /key/info
    function info() {
        try {
            $response = Requests::get(
                $this->base . '/key/info?api_key=' . $this->key, 
                array('Accept' => 'application/json')
            );
        }
        catch (Requests_Exception $e) {
            throw new SmartFilterNetworkException($e);
        }
        if ($response->status_code == 200) { return json_decode($response->body, true); }
        if ($response->status_code == 400) { throw new SmartFilterBadInputParameter(); }
        if ($response->status_code == 403) { throw new SmartFilterBadAPIKey(); }
        if ($response->status_code == 500) { throw new SmartFilterInternalError(); }
        return array();
    }

    // Endpoint: /whitelist/verify
    function verify_whitelist($whitelist) {
        try {
            $response = Requests::get(
                $this->base . '/whitelist/verify?api_key=' . $this->key . '&whitelist_id=' . $whitelist, 
                array('Accept' => 'application/json')
            );
        }
        catch (Requests_Exception $e) {
            throw new SmartFilterNetworkException($e);
        }
        if ($response->status_code == 200) { return true; }
        if ($response->status_code == 400) { throw new SmartFilterBadInputParameter(); }
        if ($response->status_code == 403) { throw new SmartFilterBadAPIKey(); }
        if ($response->status_code == 500) { throw new SmartFilterInternalError(); }
        return false;
    }

    // Endpoint: /xss/detect
    function detect($input, $whitelist) {
        try {
            $response = Requests::post(
                $this->base . '/xss/detect',
                array('Accept' => 'application/json'),
                array('api_key' => $this->key, 'input' => $input, 'whitelist_id' => $whitelist)
            );
        }
        catch (Requests_Exception $e) {
            throw new SmartFilterNetworkException($e);
        }
        if ($response->status_code == 200) { return json_decode($response->body, true); }
        if ($response->status_code == 400) { throw new SmartFilterBadInputParameter(); }
        if ($response->status_code == 403) { throw new SmartFilterBadAPIKey(); }
        if ($response->status_code == 413) { throw new SmartFilterRequestTooLarge(); }
        if ($response->status_code == 500) { throw new SmartFilterInternalError(); }
        if ($response->status_code == 507) { throw new SmartFilterAccountQuotaExceeded(); }
        return array();
    }

    // Endpoint: /xss/filter
    function filter($input, $whitelist) {
        try {
            $response = Requests::post(
                $this->base . '/xss/filter',
                array('Accept' => 'application/json'),
                array('api_key' => $this->key, 'input' => $input, 'whitelist_id' => $whitelist)
            );
        }
        catch (Requests_Exception $e) {
            throw new SmartFilterNetworkException($e);
        }
        if ($response->status_code == 200) { return json_decode($response->body, true); }
        if ($response->status_code == 400) { throw new SmartFilterBadInputParameter(); }
        if ($response->status_code == 403) { throw new SmartFilterBadAPIKey(); }
        if ($response->status_code == 413) { throw new SmartFilterRequestTooLarge(); }
        if ($response->status_code == 500) { throw new SmartFilterInternalError(); }
        if ($response->status_code == 507) { throw new SmartFilterAccountQuotaExceeded(); }
        return array();
    }
}

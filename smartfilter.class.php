<?php
require_once('lib/Requests.php');
Requests::register_autoloader();

class SmartFilterNetworkException extends Exception { }
class SmartFilterBadInputParameter extends Exception { }
class SmartFilterBadAPIKey extends Exception { }
class SmartFilterRequestTooLarge extends Exception { }
class SmartFilterInternalError extends Exception { }
class SmartFilterAccountQuotaExceeded extends Exception { }

/**
 * SmartFilter class
 *
 * Manages calls to Prevoty API
 */
class SmartFilter {
    /**
     * API key
     *
     * @var string
     */
    private $key;

    /**
     * Base URL for API requests
     *
     * @var string
     */
    private $base;

    /**
     * Array of options to be passed to each Request call
     *
     * @var array
     */
    private $options = array();

    function __construct($key) {
        $this->key = $key;
        $this->base = 'https://api.prevoty.com/1';
    }

    /**
     * Sets all options to be passed to each request
     *
     * @param array $options - All options to be passed to each request
     * @return $this - fluent interface
     */
    public function setOptions(array $options) {
        $this->options = $options;
        return $this;
    }

    /**
     * Sets an option to be passed to each request
     *
     * @param string $key - The name of the option (i.e. timeout, proxy, etc.)
     * @param mixed $value - The value of the option
     * @return $this - fluent interface
     */
    public function setOption($key, $value) {
        $this->options[$key] = $value;
        return $this;
    }

    /**
     * Gets all options that will be passed to each request.
     *
     * @return array $options
     */
    public function getOptions() {
        return $this->options;
    }

    /**
     * Verifies API key
     * Endpoint: /key/verify
     *
     * @throws SmartFilterNetworkException - Unable to connect
     * @throws SmartFilterBadInputParameter - Unknown API call
     * @throws SmartFilterBadAPIKey - Bad API key
     * @throws SmartFilterInternalError - Server error
     * @return boolean
     */
    function verify() {
        try {
            $response = Requests::get(
                $this->base . '/key/verify?api_key=' . $this->key, 
                array('Accept' => 'application/json'),
                $this->getOptions()
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

    /**
     * Returns info about Prevoty
     * Endpoint: /key/info
     *
     * @throws SmartFilterNetworkException - Unable to connect
     * @throws SmartFilterBadInputParameter - Unknown API call
     * @throws SmartFilterBadAPIKey - Bad API key
     * @throws SmartFilterInternalError - Server error
     * @return array
     */
    function info() {
        try {
            $response = Requests::get(
                $this->base . '/key/info?api_key=' . $this->key, 
                array('Accept' => 'application/json'),
                $this->getOptions()
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

    /**
     * Verifies a rule
     * Endpoint: /rule/verify
     *
     * @throws SmartFilterNetworkException - Unable to connect
     * @throws SmartFilterBadInputParameter - Unknown API call
     * @throws SmartFilterBadAPIKey - Bad API key
     * @throws SmartFilterInternalError - Server error
     * @return boolean
     */
    function verify_rule($rule_key) {
        try {
            $response = Requests::get(
                $this->base . '/rule/verify?api_key=' . $this->key . '&rule_key=' . $rule_key, 
                array('Accept' => 'application/json'),
                $this->getOptions()
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

    /**
     * Filters user input
     * Endpoint: /xss/filter
     *
     * @throws SmartFilterNetworkException - Unable to connect
     * @throws SmartFilterBadInputParameter - Unknown API call
     * @throws SmartFilterBadAPIKey - Bad API key
     * @throws SmartFilterInternalError - Server error
     * @return array
     */
    function filter($input, $rule_key) {
        try {
            $response = Requests::post(
                $this->base . '/xss/filter',
                array('Accept' => 'application/json'),
                array('api_key' => $this->key, 'input' => $input, 'rule_key' => $rule_key),
                $this->getOptions()
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

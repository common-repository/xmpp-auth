<?php
/*
{{{
    XMPP-Auth -- A Wordpress plugin to authenticate via XMPP.
    Copyright 2008;2011 Jehan Hysseo

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
}}}
*/

require_once(dirname(__FILE__) . '/Auth/SASL2.php');
require_once(dirname(__FILE__) . '/Auth/SASL2/DigestMD5.php');
require_once(dirname(__FILE__) . '/Auth/SASL2/Plain.php');
require_once(dirname(__FILE__) . '/Auth/SASL2/CramMD5.php');
require_once(dirname(__FILE__) . '/Auth/SASL2/SCRAM.php');
//require_once('./Auth/SASL2/Anonymous.php');
$old_error_level = error_reporting(0);
include_once "Net/DNS.php"; // For SRV Records. // Optional.
error_reporting($old_error_level);
require_once(dirname(__FILE__) . '/my_socket.php');
require_once(dirname(__FILE__) . '/xmpp_utils.php');

if (!class_exists('xmpp_stream')):
class xmpp_stream // {{{
{
	protected $node = '';
	protected $domain = '';
	private $password = '';
	protected $resource = '';
	// real jid obtained after authentication.
	public $jid = ''; // TODO: make a method to get this.

    protected $targets = array();
	protected $socket = null;
    protected $cached_srv = FALSE;

	protected $logged = FALSE;
    protected $xml_parser = NULL;
    private $callbacks = array();
    private $dom = NULL;

	// If nothing happens on the stream after 30 seconds, I shutdown.
	private $timeout = 30;
	public $last_error = '';

	// Known authentication mechanism.
	// The key is the mechanism name, and the value is the preference.
	// The more securized, the preferred mechanism...
	// For now will consider only the digest-md5 authentication.
	private $known_auth = array ('DIGEST-MD5' => 6, 'CRAM-MD5' => 8, 'PLAIN' => 4, 'SCRAM-SHA-1' => 10);
	private $chosen_mechanism = '';
	private $use_tls = false;

	private $current_cdata = '';
	private $features = array ();
	private $ids = array ();

	// FLAGS //
	protected $flags = array ();

	function __construct($node, $domain, $password,
        $resource = 'bot', $server = NULL, $port = NULL) // {{{
	{
        require_once(dirname(__FILE__) . '/dns.php');
        $this->dom = new DOMDocument('1.0', 'utf-8');
		$this->node = $node;
		$this->domain = $domain;
		$this->password = $password;
		$this->resource = $resource;

		if (empty($port) && empty($server))
		{
            $cache = get_option('imauth_dns_srv_cache');
            if (isset($cache[$domain]) && $cache[$domain][0]['ttl'] >= time())
            {
                // I make the check of the domain, because the domain may have changed.
                // Also I know (from the way I built the cache) that if it exists, it will always have at least one value,
                // at index 0, and that if there are several values, the 'ttl' will be the same for all of them.
                $this->targets = $cache[$domain];
            }
			elseif (class_exists("NET_DNS_Resolver"))
			{
				$resolver = new Net_DNS_Resolver();
				$response = $resolver->query('_xmpp-client._tcp.' . $this->domain, 'SRV');
				if (!empty($response))
				{
					$recs = array ();
					foreach ($response->answer as $rr)
					{
                        if ($rr->type <> 'SRV')
                            continue;
						$rec = array ();
                        $rec['type'] = 'SRV';
						$rec['target'] = $rr->target;
						$rec['port'] = $rr->port;
						$rec['weight'] = $rr->weight;
						$rec['ttl'] = $rr->ttl;
						// for some unknown reason, in NET_DNS, priority is called preference.
                        $rec['pri'] = $rr->preference;
                        $recs[] = $rec;
					}
					$this->targets = dns_srv_sort($recs);
                    $cache = array($domain => $this->targets);
                    $this->cached_srv = TRUE;
                    update_option('imauth_dns_srv_cache', $cache);
				}
				else
                    $this->targets[] = array(
                        'port' => 5222,
                        'server' => $domain);
			}
			elseif (function_exists ("dns_get_record"))
			{
				$response = dns_get_record('_xmpp-client._tcp.' . $this->domain, DNS_SRV);
				if (!empty($response))
                {
					$this->targets = dns_srv_sort($response);
                    $cache = array($domain => $this->targets);
                    $this->cached_srv = TRUE;
                    update_option('imauth_dns_srv_cache', $cache);
                }
				else
                    $this->targets[] = array(
                        'port' => 5222,
                        'server' => $domain);
			}
			else
                $this->targets[] = array(
                    'port' => 5222,
                    'server' => $domain);
		}
		else
		{
			if ($server == '')
				$server = $domain;

			if ($port == '')
				$port = 5222;

            $this->targets[] = array(
                'port' => $port,
                'server' => $server);
		}
	} // }}}

	// For backwards compatibility in php4.
	function xmpp_stream ($node, $domain, $password, $resource,
		$server = '', $port = 5222) // {{{
	{
		$this->__construct ($node, $domain, $password, $server, $port);
		register_shutdown_function (array (&$this, "__destruct"));
	} // }}}

	function __destruct () // {{{
	{
		if ($this->logged)
			$this->quit ();
	} // }}}

    public function raw_send($stanza)
    {
		if (!$this->socket->send($stanza))
		{
			$this->last_error = __("Stanza could not be sent: \n", 'xmpp-auth');
            $this->last_error .= $stanza;
            $this->last_error .= "\n with error:\n";
			$this->last_error .= $this->socket->last_error;
			$this->quit ();
			return FALSE;
		}
        return TRUE;
    }

    public function reset_callbacks()
    {
        $this->callbacks = array();
    }

    /**
     * @param callback $callback a function which must accept 2 parameters and a third optional parameter:
     * a reference to the xmpp_stream itself and a DOMElement representing an incoming stanza.
     * The third parameter must be passed by reference in the callback signature and will be NULL.
     * If the callback modify it, it means a terminale condition of the run, any value which will be returned by run().
     * This allows you to return either details about a failure (in a string of some object/array), or even details
     * on a successful run.
     * This callback must return TRUE if it handled the stanza and does not want any other callback to process it,
     * FALSE if it did not handle it, or did process it but wish to let it to other callbacks too,
     * anything else then a boolean if a terminale condition occurred.
     */
    public function add_callback($callback, $params = NULL)
    {
        $this->callbacks[] = array('cb' => $callback, 'params' => $params);
    }

    /*public function remove_callback($callback)
    {
        if ($key = array_search($callback, $this->callbacks, false))
            unset($this->callbacks[$key]);
        return;
    }*/

    public function run($timeout = NULL)
    {
        if (!is_null($timeout) && is_numeric($timeout))
            $this->timeout = intval($timeout);

        $this->level = 1;
        $this->terminale = NULL;
		$this->process_read('stanza_start_handler', 'stanza_end_handler', 'stanza');
        return $this->terminale;
    }

	private function stanza_start_handler($parser, $name, $attrs) // {{{
	{
        $namespace = '';
        $localpart = $name;

        $sep = strrpos($name, ':');
        if ($sep !== FALSE)
        {
            $localpart = substr($name, $sep + 1);
            $namespace = substr($name, 0, $sep);
        }

        $new_elt = $this->dom->createElementNS($namespace, $localpart);
        foreach ($attrs as $attr => $value)
        {
            $attr_ns = '';
            $attr_lp = $attr;
            $sep = strrpos($attr, ':');
            if ($sep !== FALSE)
            {
                $attr_lp = substr($attr, $sep + 1);
                $attr_ns = substr($attr, 0, $sep);
            }
            $new_elt->setAttributeNS($attr_ns, $attr_lp, $value);
        }

        if ($this->level++ == 1)
        {
            $this->stanza = $new_elt;
            $this->stanza_ptr = $new_elt;
        }
        else
        {
            if ($this->current_cdata <> '')
            {
                $text = new DOMText($this->current_cdata);
                $this->stanza_ptr->appendChild($text);
            }
            $this->stanza_ptr->appendChild($new_elt);
            $this->stanza_ptr = $new_elt;
        }
		$this->current_cdata = '';
	} // }}}

	private function stanza_end_handler($parser, $name) // {{{
	{
        if ($this->current_cdata <> '')
        {
            $text = new DOMText($this->current_cdata);
            $this->stanza_ptr->appendChild($text);
        }

        if (--$this->level == 1)
        {
            jabber_feed_log("NEW STANZA:\n" . $this->dom->saveXML($this->stanza));

            foreach($this->callbacks as $cb)
            {
                if (is_callable($cb['cb']))
                {
                    $this->terminale = NULL;
                    $break = call_user_func_array($cb['cb'], array($this, $this->stanza, $cb['params'], &$this->terminale));
                    if (!is_null($this->terminale))
                    {
                        $this->flags['stanza'] = TRUE;
                        return;
                    }

                    if ($break)
                        break;

                    continue;
                }
                jabber_feed_log('This callback is not callable: ' . print_r($cb['cb'], TRUE));
            }
            $this->stanza == NULL;
        }
        else
            $this->stanza_ptr = $this->stanza_ptr->parentNode;
	} // }}}

	// All these functions return false when the operation did not succeed.

	public function log() // {{{
	{
		if (!$this->logged && $this->connect() && $this->authenticate() && $this->bind() && $this->session_establish())
			$this->logged = true;
		
		return $this->logged;
	} // }}}

	public function quit() // {{{
	{
		if ($this->logged)
        {
			$this->socket->close();
            $this->logged = FALSE;
        }
		unset($this->flags);
        if ($this->xml_parser)
            xml_parser_free($this->xml_parser);
		return true;
	} // }}}

	protected function connect() // {{{
	{
		$this->socket = new my_socket();
		foreach ($this->targets as $k => $target)
		{
			$this->socket->server = $target['server'];
			$this->socket->port = $target['port'];

			if (!$this->socket->connect())
			{
				$this->last_error = __('Error during connection: ', 'xmpp-auth') . $this->socket->last_error;
				continue;
			}
            if ($this->cached_srv && $k > 0)
            {
                // If some attempts failed and I cached records, I want to reorganize them.
                // I put the succeded record first for next time, and the failure at the end.
                function success_first($k1, $k2)
                {
                    if ($k1 == $k2)
                        return 0;
                    // The working key is always the smaller one.
                    if ($k1 == $k)
                        return -1;
                    if ($k2 == $k)
                        return 1;
                    // Any of the keys which failed must be at the end.
                    if ($k1 < $k && $k2 < $k)
                        return 0;
                    if ($k1 > $k && $k2 > $k)
                        return 0;
                    if ($k1 < $k)
                        return 1;
                    if ($k2 < $k)
                        return -1;
                    else
                        return 0; // other than this, I don't care.
                }
                uksort($this->targets, 'success_first');
                $cache = array($domain => $this->targets);
                update_option('imauth_dns_srv_cache', $cache);
            }

			return true;
		}

		return false;
	} // }}}
	
	private function authenticate() // {{{
	{
        // TODO: add a xml:lang?
		$stream_begin = "<stream:stream xmlns='jabber:client'
			xmlns:stream='http://etherx.jabber.org/streams'
			to='" . $this->domain .
			"' version='1.0'>";

		if (! $this->socket->send($stream_begin))
		{
			$this->last_error = __('Stream initiation failure: ', 'xmpp-auth');
			$this->last_error .= $this->socket->last_error;
			$this->quit();
			return false;
		}

		return $this->process_read("authentication_start_handler",
			"authentication_end_handler", 'authenticated');
	} // }}}

	private function bind() // {{{
	{
		$stream_begin = "<stream:stream xmlns='jabber:client'
			xmlns:stream='http://etherx.jabber.org/streams'
			to='" . $this->domain .
			"' version='1.0'>";

		if (! $this->socket->send ($stream_begin))
		{
			$this->last_error = __('Binding failure: ', 'xmpp-auth');
			$this->last_error .= $this->socket->last_error;
			$this->quit ();
			return false;
		}
        xml_parser_free($this->xml_parser);
        $this->xml_parser = NULL;
		//elseif (array_key_exists ('bind', $this->features)) // TODO
			return ($this->process_read ("binding_start_handler",
				"binding_end_handler", 'bound'));
		//else
		{
			$this->last_error = 'Bind feature not available on the remote server.';
			return false;
		}
	} // }}}

	private function session_establish () // {{{
	{
		// Session establishement is deprecated in RFC-6120.
		// But for the sake of compatibility, I negotiate it if present.
		if (array_key_exists ('urn:ietf:params:xml:ns:xmpp-session:session', $this->features))
		{
			$id = time () . rand ();
			$this->ids['session'] = 'session' . $id;
			$message_session = "<iq to='" . $this->domain ."' type='set' id='session" . $id . "'>";
			$message_session .= "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/></iq>";
			$this->socket->send ($message_session);

			return ($this->process_read ("session_start_handler",
				"session_end_handler", 'session'));
		}
		else
			// if the server does not support session, so we just continue without session establishment!
			return true;
	} // }}}

    protected function flag_for_reset($start_element_handler, $end_element_handler, $flag)
    {
        $this->reset_flag = array($start_element_handler, $end_element_handler, $flag);
    }

    protected function reset()
    {
        if ($this->xml_parser)
            xml_parser_free ($this->xml_parser);
        $this->xml_parser = xml_parser_create_ns('UTF-8', ':');
        xml_parser_set_option($this->xml_parser, XML_OPTION_CASE_FOLDING, 0);
		xml_set_element_handler($this->xml_parser,
			array (&$this, $this->reset_flag[0]),
			array (&$this, $this->reset_flag[1]));
		xml_set_character_data_handler ($this->xml_parser, array (&$this, "cdata_handler"));
        unset($this->reset_flag);
    }

    // parse data from the socket according to given handlers until $flag is true.
	protected function process_read($start_element_handler,
		$end_element_handler, $flag) // {{{
	{
        if (!$this->xml_parser)
        {
            $this->xml_parser = xml_parser_create_ns('UTF-8', ':');
            xml_parser_set_option($this->xml_parser, XML_OPTION_CASE_FOLDING, 0);
        }
		xml_set_element_handler($this->xml_parser,
			array (&$this, $start_element_handler),
			array (&$this, $end_element_handler));
		xml_set_character_data_handler ($this->xml_parser, array (&$this, "cdata_handler"));

		$last_update = time ();
		while (true)
		{
			if (array_key_exists ($flag, $this->flags))
				break;
            if (isset($this->reset_flag))
                $this->reset();

			$data = $this->socket->read();

			if ($data === FALSE)
			{
				$this->last_error = __('Error while reading in the socket.', 'xmpp-auth');
				jabber_feed_log ($this->last_error);
				break;
			}
			elseif (strlen($data) === 0)
			{
				if (time() - $last_update > $this->timeout)
				{
					$this->last_error =  __('Timeout of ', 'xmpp-auth') . ' ';
					$this->last_error .= $this->timeout ;
					$this->last_error .= ' ' . __('seconds.', 'xmpp-auth');
					jabber_feed_log ($this->last_error);
					break;
				}
				continue;
			}
			elseif (xml_parse($this->xml_parser, $data, FALSE) === 0)
			{
				jabber_feed_log ('Incoming XML failed to parse: ' . $data);
				$this->last_error = sprintf("XML parsing error %d %d: %s at line %d (\"%s\").",
					xml_get_error_code ($this->xml_parser),
					XML_ERROR_INVALID_TOKEN,
					xml_error_string(xml_get_error_code ($this->xml_parser)),
					xml_get_current_line_number ($this->xml_parser),
					htmlentities ($data));
				jabber_feed_log ($this->last_error);
				break;
			}
			else // data read on the socket and processed in the handlers if needed!
			{
				$xmpp_last_update = time ();
				continue;
			}
		}

		//xml_parser_free ($this->xml_parser);
		if (array_key_exists ($flag, $this->flags))
		{
			$return_value = $this->flags[$flag];
			unset ($this->flags[$flag]);
			return $return_value;
		}
		else
			return false;
	} // }}}

	///////////////////////
	// All the handlers! //
	///////////////////////

	private function cdata_handler ($parser, $data) // {{{
	{
		$this->current_cdata .= $data;
	} // }}}

	protected function common_start_handler ($name) // {{{
	{
		$this->current_cdata = '';
	} // }}}

	protected function common_end_handler () // {{{
	{
		return;
	} // }}}

// Authentication //

	private function authentication_start_handler ($parser, $name, $attrs) // {{{
	{
		$this->common_start_handler ($name);
	} // }}}

	private function authentication_end_handler ($parser, $name) // {{{
	{
		$this->common_end_handler ();
		if ($name == 'urn:ietf:params:xml:ns:xmpp-tls:starttls')
		{
			$this->use_tls = true;
			$this->flags['starttls'] = true;
			return;
		}
		elseif ($name == 'urn:ietf:params:xml:ns:xmpp-sasl:mechanism' && array_key_exists(strtoupper($this->current_cdata), $this->known_auth))
		{
			$this->current_cdata = strtoupper ($this->current_cdata);
			if (empty($this->chosen_mechanism) || $this->known_auth[$this->current_cdata] > $this->known_auth[$this->chosen_mechanism])
				$this->chosen_mechanism = $this->current_cdata;
			return;
		}
		elseif ($name == 'urn:ietf:params:xml:ns:xmpp-sasl:challenge'
			&& ! array_key_exists ('challenged_once', $this->flags))
		{
			// I get the challenge from cdata and decode it (base64).
			$decoded_challenge = base64_decode ($this->current_cdata);
			if ($this->chosen_mechanism == "DIGEST-MD5")
			{
				$sasl = new Auth_SASL2_DigestMD5 ();
				$uncoded = $sasl->getResponse ($this->node, $this->password, $decoded_challenge, $this->domain, 'xmpp');

				$coded = base64_encode ($uncoded);
				$response = '<response xmlns=\'urn:ietf:params:xml:ns:xmpp-sasl\'>' . $coded . '</response>';

				if (! $this->socket->send ($response))
				{
					$this->last_error = __('Authentication failure: ', 'xmpp-auth');
					$this->last_error .= $_socket->last_error;
					$this->flags['authenticated'] = false;
					return;
				}

			}
			elseif ($this->chosen_mechanism == "SCRAM-SHA-1")
			{
                // Apparently that never gets used!
                if (!isset($this->sasl))
                    $this->sasl = new Auth_SASL2_SCRAM('SHA-1');
				$uncoded = $this->sasl->getResponse ($this->node, $this->password, $decoded_challenge);

				$coded = base64_encode ($uncoded);
				$response = '<response xmlns=\'urn:ietf:params:xml:ns:xmpp-sasl\'>' . $coded . '</response>';

				if (! $this->socket->send ($response))
				{
					$this->last_error = __('Authentication failure: ', 'xmpp-auth');
					$this->last_error .= $_socket->last_error;
					$this->flags['authenticated'] = false;
					return;
				}
			}
			elseif ($this->chosen_mechanism == "CRAM-MD5")
			{
				$sasl = new Auth_SASL2_CramMD5 ();
				$uncoded = $sasl->getResponse ($this->node, $this->password, $decoded_challenge);
				// To be tested. Should the first argument be full jid or just username?

				$coded = base64_encode ($uncoded);
				$response = '<response xmlns=\'urn:ietf:params:xml:ns:xmpp-sasl\'>' . $coded . '</response>';

				if (! $this->socket->send ($response))
				{
					$this->last_error = __('Authentication failure: ', 'xmpp-auth');
					$this->last_error .= $_socket->last_error;
					$this->flags['authenticated'] = false;
					return;
				}

			}
			elseif ($this->chosen_mechanism == "ANONYMOUS")
			{
				$sasl = new Auth_SASL2_Anonymous ();
				$uncoded = $sasl->getResponse ();
			}

			$this->flags['challenged_once'] = true;
			return;
		}
		elseif ($name == 'urn:ietf:params:xml:ns:xmpp-sasl:challenge')
		{
            // Never gets here either.
			unset ($this->flags['challenged_once']);
			$response = '<response xmlns=\'urn:ietf:params:xml:ns:xmpp-sasl\'/>';
			if (! $this->socket->send ($response))
			{
				$this->last_error = __('Authentication failure: ', 'xmpp-auth');
				$this->last_error .= $_socket->last_error;
				$this->flags['authenticated'] = false;
				return;
			}
		}
		elseif ($name == 'urn:ietf:params:xml:ns:xmpp-sasl:failure' || $name == 'http://etherx.jabber.org/streams:stream')
		{
			$this->socket->send ('</stream:stream>');
			$this->last_error = __('Authentication failure: wrong username or password.', 'xmpp-auth');
			$this->flags['authenticated'] = false;
			return;
		}
		elseif ($name == 'urn:ietf:params:xml:ns:xmpp-sass:success')
		{
			$this->flags['authenticated'] = true;
			return;
		}
		elseif ($name == 'http://etherx.jabber.org/streams:features'
				&& array_key_exists ('starttls', $this->flags))
		{
			// I must discard any information got before TLS negotiation.
			$this->chosen_mechanism = '';

			$tls_query = '<starttls xmlns="urn:ietf:params:xml:ns:xmpp-tls"/>';
			if (! $this->socket->send ($tls_query))
			{
				$this->last_error = __('Authentication failure: ', 'xmpp-auth');
				$this->last_error .= $this->socket->last_error;
				$this->flags['authenticated'] = false;
				return;
			}
			return;
		}
		elseif ($name == 'urn:ietf:params:xml:ns:xmpp-tls:proceed'
				&& array_key_exists ('starttls', $this->flags))
		{
			unset ($this->flags['starttls']);

			if (!$this->socket->encrypt ())
			{
				$this->last_error = __('Authentication failure: ', 'xmpp-auth');
				$this->last_error .= $this->socket->last_error;
				$this->flags['authenticated'] = false;
				return;
			}

			jabber_feed_log ("Encrypted connection.");
			
			$stream_begin2 = "<stream:stream xmlns='jabber:client'
				xmlns:stream='http://etherx.jabber.org/streams'
				to='" . $this->domain .
				"' version='1.0'>";

			if (! $this->socket->send($stream_begin2))
			{
				$this->last_error = __('Stream initiate failure after TLS successful: ', 'xmpp-auth');
				$this->last_error .= $this->socket->last_error;
				$this->quit();
				$this->flags['authenticated'] = false;
				return;
			}

            $this->flag_for_reset("authentication_tls_start_handler",
						"authentication_tls_end_handler", 'authenticated_tls');
			/*if ($this->process_read ("authentication_tls_start_handler",
						"authentication_tls_end_handler", 'authenticated_tls'))
			{
				$this->flags['authenticated'] = true;
				return;
			}
			else
			{
				$this->flags['authenticated'] = false;
				return;
			}*/
		}
		elseif ($name == 'http://etherx.jabber.org/streams:features')
		{
			jabber_feed_log ("Chosen authentication mechanism: " . $this->chosen_mechanism);
			if ($this->chosen_mechanism == '')
			{
				$this->last_error = __('No compatible authentication mechanism.', 'xmpp-auth');
				jabber_feed_log ($this->last_error);
				$this->flags['authenticated'] = false;
			}
			else
			{
				if ($this->chosen_mechanism == "PLAIN")
				{
					$sasl = new Auth_SASL2_Plain ();
					$uncoded = $sasl->getResponse ($this->node . '@' . $this->domain, $this->password);

					$coded = base64_encode ($uncoded);

					$mechanism = "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>";
					$mechanism .= $coded . "</auth>";
				}
                elseif ($this->chosen_mechanism == "SCRAM-SHA-1")
                {
                    // Apparently I don't come here!
                    if (!isset($this->sasl))
                        $this->sasl = new Auth_SASL2_SCRAM('SHA-1');
                    $uncoded = $this->sasl->getResponse ($this->node, $this->password);
					$coded = base64_encode ($uncoded);

					$mechanism = "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>";
					$mechanism .= $coded . "</auth>";
                }
				else
				{
					$mechanism = "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'";
					$mechanism .= " mechanism='" . $this->chosen_mechanism . "' />";
				}

				$this->socket->send ($mechanism);
			}
			return;
		}

	} // }}}

	private function authentication_tls_start_handler($parser, $name, $attrs) // {{{
	{
		$this->common_start_handler ($name);
	} // }}}

	private function authentication_tls_end_handler($parser, $name) // {{{
	{
		$this->common_end_handler();

        jabber_feed_log("CDATA " . $this->current_cdata);
		if ($name == 'urn:ietf:params:xml:ns:xmpp-sasl:mechanism' && array_key_exists(strtoupper($this->current_cdata), $this->known_auth))
		{
			$this->current_cdata = strtoupper ($this->current_cdata);
			if (empty($this->chosen_mechanism) || $this->known_auth[$this->current_cdata] > $this->known_auth[$this->chosen_mechanism])
				$this->chosen_mechanism = $this->current_cdata;
			return;
		}
		elseif ($name == 'urn:ietf:params:xml:ns:xmpp-sasl:challenge')
			//&& ! array_key_exists ('challenged_once', $this->flags))
		{
			// I get the challenge from cdata and decode it (base64).
			$decoded_challenge = base64_decode ($this->current_cdata);
			if ($this->chosen_mechanism == "DIGEST-MD5")
			{
			    if (array_key_exists ('challenged_once', $this->flags))
                    $uncoded = '';
                else
                {
                    $sasl = new Auth_SASL2_DigestMD5 ();
                    $uncoded = $sasl->getResponse ($this->node, $this->password, $decoded_challenge, $this->domain, 'xmpp');
                }
			}
			elseif ($this->chosen_mechanism == "SCRAM-SHA-1")
			{
                if (!isset($this->sasl))
                    $this->sasl = new Auth_SASL2_SCRAM('SHA-1');
				$uncoded = $this->sasl->getResponse ($this->node, $this->password, $decoded_challenge);
			}
			elseif ($this->chosen_mechanism == "CRAM-MD5")
			{
				$sasl = new Auth_SASL2_CramMD5 ();
				$uncoded = $sasl->getResponse ($this->node, $this->password, $decoded_challenge);
				// To be tested. Should the first argument be full jid or just username?
			}
			elseif ($this->chosen_mechanism == "ANONYMOUS")
			{
				$sasl = new Auth_SASL2_Anonymous ();
				$uncoded = $sasl->getResponse ();
			}
			else
			{
				$this->last_error = __('Authentication failure: ', 'xmpp-auth');
				$this->last_error .= __('this case should never happen. Contact the developper.', 'xmpp-auth');
				$this->flags['authenticated_tls'] = false;
				return;
			}

			$coded = base64_encode ($uncoded);
			$response = '<response xmlns=\'urn:ietf:params:xml:ns:xmpp-sasl\'>' . $coded . '</response>';

			if (! $this->socket->send ($response))
			{
				$this->last_error = __('Authentication failure: ', 'xmpp-auth');
				$this->last_error .= $_socket->last_error;
				$this->flags['authenticated_tls'] = false;
				return;
			}
			
			$this->flags['challenged_once'] = true;
			return;
		}
		elseif ($name == 'urn:ietf:params:xml:ns:xmpp-sasl:challenge')
		{
			unset ($this->flags['challenged_once']);
			$response = '<response xmlns=\'urn:ietf:params:xml:ns:xmpp-sasl\'/>';
			if (! $this->socket->send ($response))
			{
				$this->last_error = __('Authentication failure: ', 'xmpp-auth');
				$this->last_error .= $_socket->last_error;
				$this->flags['authenticated_tls'] = false;
				return;
			}
		}
		elseif ($name == 'urn:ietf:params:xml:ns:xmpp-sasl:failure' || $name == 'http://etherx.jabber.org/streams:stream')
		{
			$this->socket->send ('</stream:stream>');
			$this->last_error = __('Authentication failure: wrong username or password.', 'xmpp-auth');
			$this->flags['authenticated_tls'] = false;
			return;
		}
		elseif ($name == 'urn:ietf:params:xml:ns:xmpp-sasl:success')
		{
			//$this->flags['authenticated_tls'] = true;
			$this->flags['authenticated'] = true;
			return;
		}
		elseif ($name == 'http://etherx.jabber.org/streams:features')
		{
			jabber_feed_log ("Chosen authentication mechanism: " . $this->chosen_mechanism);
			if ($this->chosen_mechanism == '')
			{
				$this->last_error = __('No compatible authentication mechanism.', 'xmpp-auth');
				jabber_feed_log ($this->last_error);
				$this->flags['authenticated_tls'] = false;
			}
			else
			{
				if ($this->chosen_mechanism == "PLAIN")
				{
					$sasl = new Auth_SASL2_Plain ();
					$uncoded = $sasl->getResponse ($this->node . '@' . $this->domain, $this->password);

					$coded = base64_encode ($uncoded);

					$mechanism = "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>";
					$mechanism .= $coded . "</auth>";
				}
                elseif ($this->chosen_mechanism == "SCRAM-SHA-1")
                {
                    if (!isset($this->sasl))
                    {
                        //$this->sasl = new Auth_SASL2_SCRAM('SHA-1');
                        $sasl = new Auth_SASL2();
                        $this->sasl = $sasl->factory('SCRAM-SHA-1');
                    }
                    $uncoded = $this->sasl->getResponse ($this->node, $this->password);
					$coded = base64_encode ($uncoded);

					$mechanism = "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>";
					$mechanism .= $coded . "</auth>";
                }
				else
				{
					$mechanism = "<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl'";
					$mechanism .= " mechanism='" . $this->chosen_mechanism . "' />";
				}

				if (! $this->socket->send ($mechanism))
				{
					$this->last_error = __('Authentication failure: ', 'xmpp-auth');
					$this->last_error .= $this->socket->last_error;
					$this->flags['authenticated_tls'] = false;
					return;
				}
			}
			return;
		}

	} // }}}

// Binding Resource //

	private function binding_start_handler ($parser, $name, $attrs) // {{{
	{
		if ($name == 'http://etherx.jabber.org/streams:features')
			$this->flags['features'] = true;
		elseif ($name == 'jabber:client:iq' && $attrs['type'] == 'result' && $this->ids['bind'] == $attrs['id'])
		{
			unset ($this->ids['bind']);
			$this->flags['resource'] = true;
		}
		elseif ($name == 'jabber:client:iq' && $attrs['type'] == 'error' && $this->ids['bind'] == $attrs['id'])
		{
			unset ($this->ids['bind']);
			$this->flags['resource_error'] = true;
		}
		elseif ($name == 'jabber:client:error' && array_key_exists ('resource_error', $this->flags))
		{
			unset ($this->flags['resource_error']);
			$this->last_error = __('Resource binding returned an error of type "', 'xmpp-auth') . $attrs['type'] . '".';
			$this->flags['bound'] = false;
		}
		$this->common_start_handler ($name);
	} // }}}

	private function binding_end_handler ($parser, $name) // {{{
	{
		$this->common_end_handler ();
		if ($name == 'http://etherx.jabber.org/streams:features')
		{
			unset ($this->flags['features']);
			if (array_key_exists ('urn:ietf:params:xml:ns:xmpp-bind:bind', $this->features))
			{
				$id = time ();
				$message = "<iq type='set' id='" . $id . "'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>";
				$message .= "<resource>" . $this->resource . $id . "</resource></bind></iq>";
				$this->ids['bind'] = $id;
				if (! $this->socket->send ($message))
				{
					$this->last_error = __('Failure during binding.', 'xmpp-auth') . '<br />';
					$this->last_error .= $this->socket->last_error;
					$this->flags['bound'] = false;
				}
			}
			else 
			{
				$this->last_error = __('Bind feature not available.', 'xmpp-auth');
				$this->flags['bound'] = false;
			}
		}
		elseif (array_key_exists ('features', $this->flags))
			$this->features[$name] = true;
		elseif ($name == 'urn:ietf:params:xml:ns:xmpp-bind:jid' && array_key_exists ('resource', $this->flags))
			$this->jid = $this->current_cdata;
		elseif ($name == 'jabber:client:iq' && array_key_exists ('resource', $this->flags))
		{
			unset ($this->flags['resource']);
			$this->flags['bound'] = true;
		}
	} // }}}

// Session //

	private function session_start_handler ($parser, $name, $attrs) // {{{
	{
		if ($name == 'jabber:client:iq' && $attrs['type'] == 'result' && $this->ids['session'] == $attrs['id'])
		{
			unset ($this->ids['session']);
			$this->flags['session_success'] = true;
		}
		elseif ($name == 'jabber:client:iq' && $attrs['type'] == 'error' && $this->ids['session'] == $attrs['id'])
		{
			unset ($this->ids['session']);
			$this->flags['session_error'] = true;
		}
		elseif ($name == 'jabber:client:error' && array_key_exists ('session_error', $this->flags))
		{
			unset ($this->flags['session_error']);
			$this->last_error = __('Session establishment returned an error of type "', 'xmpp-auth') . $attrs['type'] . '".';
			$this->flags['session'] = false;
		}
			
		$this->common_start_handler ($name);
	} // }}}

	private function session_end_handler ($parser, $name) // {{{
	{
		$this->common_end_handler ();
		if ($name == 'jabber:client:iq' && array_key_exists ('session_success', $this->flags))
		{
			unset ($this->flags['session_success']);
			$this->flags['session'] = true;
		}
	} // }}}

    /****** TODO: avatar. ******/

	public function retrieve_avatar($jid) // {{{
	{
		$iq_id = time () . rand (); // Is it random enough? Probably for such use...
		$this->flags['avatar'] = $iq_id;
		$this->flags['avatar_recipient'] = $jid;

		$query = "<iq type='get' from='" . $this->jid . "' ";
		$query .= "to='" . $jid . "' id='" . $iq_id . "'>";
		$query .= "<thread>" . $iq_id . "</thread>";
		$query .= "<body>" . $readable_message . "</body>";

		$message .= "<confirm xmlns='http://jabber.org/protocol/http-auth'  id='$transaction_id' method='$http_method' url='$http_url'/></message>";


		if (! $this->socket->send ($query))
		{
			$this->last_error = __('HTTP authentication failure: ', 'xmpp-auth');
			$this->last_error .= $this->socket->last_error;
			$this->quit ();
			return FALSE;
		}

		return ($this->process_read ("avatar1_start_handler",
			"avatar1_end_handler", 'http_authenticated'));
	} // }}}

	private function avatar1_start_handler ($parser, $name, $attrs) // {{{
	{
		if ($name == 'jabber:client:message' && $attrs['type'] == 'error'
			&& xmpp_bare_jid($attrs['from']) == xmpp_bare_jid($this->flags['http_auth_recipient'])) // TODO: thread!
		{
			//unset ($this->ids['http_auth']);
			$this->flags['http_auth_error'] = true;
		}
		elseif ($name == 'jabber:client:message'
			&& xmpp_bare_jid($attrs['from']) == xmpp_bare_jid($this->flags['http_auth_recipient']))
		{
			$this->flags['http_auth_more'] = true;
			// TODO: check if there is a textual message. If so, it must be "OK"/"NO".
			// ELSE check the <confirm/>
		}
		elseif ($name == 'CONFIRM' &&
			(isset($this->flags['http_auth_more']) || isset($this->flags['http_auth_error'])))
		{ // TODO check method and url and ns.
			if (html_entity_decode($attrs['id']) == $this->flags['http_auth'])
				$this->flags['same_request_confirmed'] = true;
			else
				$this->flags['same_request_confirmed'] = false;
		}
		elseif ($name == 'ERROR' && (isset($this->flags['http_auth_error'])
			|| isset($this->flags['http_auth_more'])))
			// This one should not happen.
			// Let's say that if it does, that's an error, so the authentication fails.
		{
			// TODO: check the thread and error code.
			//unset ($this->flags['http_auth_error']);
			$this->last_error = __('Publication returned an error of type "', 'xmpp-auth') . $attrs['type'] . '".';
			$this->flags['http_authenticated'] = false;
		}

		$this->common_start_handler ($name);
	} // }}}
	
	private function avatar1_end_handler ($parser, $name) // {{{
	{
		if ($name == 'jabber:client:thread' &&
			(isset($this->flags['http_auth_more']) || isset($this->flags['http_auth_error'])))
		{
			if ($this->flags['http_auth_thread'] == $this->current_cdata)
			{
				// TODO: check if there is a textual message. If so, it must be "OK"/"NO".
				// ELSE check the <confirm/>
				//unset ($this->ids['http_auth']);
				//$this->flags['http_authenticated'] = true;
				$this->flags['thread_confirmed'] = true;
			}
			else
				$this->flags['thread_confirmed'] = false;
		}
		elseif ($name == 'jabber:client:body' && array_key_exists ('http_auth_more', $this->flags))
		{
			if (trim(strtolower($this->current_cdata)) == "no")
			{
				$this->flags['body_denied'] = true;
			}
			elseif (trim(strtolower($this->current_cdata)) == "ok")
			{
				$this->flags['body_confirmed'] = true;
			}
		}
		elseif ($name== 'jabber:client:message' && array_key_exists ('http_auth_more', $this->flags))
		{
			if (isset($this->flags['thread_confirmed']) && $this->flags['thread_confirmed'])
			{
				if (isset($this->flags['body_denied']))
					$this->flags['http_authenticated'] = false;
				//elseif (isset($this->flags['http_auth_error']))
				//	$this->flags['http_authenticated'] = false;
				// if (isset($this->flags['body_confirmed'])) || nothing set.
				elseif (isset($this->flags['body_confirmed'])
					|| $this->flags['same_request_confirmed'])
					$this->flags['http_authenticated'] = true;
			}
		}
		elseif ($name== 'jabber:client:message' && array_key_exists ('http_auth_error', $this->flags))
			$this->flags['http_authenticated'] = false;
		
		$this->common_end_handler ();
	} // }}}

    /***** TODO: I leave this only not (hopefully) to break Jabber Feed. Will have to get into it later. */

	public function notify ($server, $node, $id, $title, $link,
		$content = '', $excerpt = '', $xhtml = true) // {{{
	{
		if (! $this->create_leaf ($server, $node))
			return false;
			
		if (version_compare (phpversion (), '5') == -1)
		{
			if (intval (date ('Z')) < 0)
				$date = date ('Y-m-d\TH:i:sZ'); // RFC3339 for PHP4 
			else
				$date = date ('Y-m-d\TH:i:s+Z'); 
		}
		else
			$date = date ('c'); // in PHP5 only! ISO 8601 = RFC3339

		$iq_id = time () . rand (); // Is it random enough? Probably for such use...
		$this->ids['publish'] = 'publish' . $iq_id;

		$message = "<iq type='set' from='" . $this->jid . "' ";
		$message .= "to='" . $server . "' id='publish" . $iq_id . "'>";
		$message .= "<pubsub xmlns='http://jabber.org/protocol/pubsub'>";
		$message .= "<publish node='" . $node;
		$message .= "'><item id='" . $id . "'><entry xmlns='http://www.w3.org/2005/Atom'>";
		$message .= "<title>" . xhtml2bare ($title) . "</title>";
		if ($excerpt !== '') // I don't know if it is possible to have xhtml excerpt in Wordpress. But let's say the plugin always send only text version.
			$message .= "<summary>" . xhtml2bare ($excerpt) . "</summary>";

		if ($content !== '')
		{
			if ($xhtml)
				$message .= '<content type="xhtml"><html xmlns="http://www.w3.org/1999/xhtml">' . fixxhtml ($content) . '</html></content>';
				
			
			$message .= '<content>' . xhtml2bare ($content) . "</content>";
		}

      $message .= '<link rel="alternate" type="text/html" href="';
		$message .= $link . '"/>';
		$message .= "<id>" . $id . "</id>";
		$message .= "<published>" . $date . "</published><updated>" . $date . "</updated>";
		// TODO: what about modified items for 'published' field??
		$message .= "</entry></item></publish></pubsub></iq>";

		if (! $this->socket->send ($message))
		{
			$this->last_error = __('Notification failure: ', 'xmpp-auth');
			$this->last_error .= $this->socket->last_error;
			$this->quit ();
			return FALSE;
		}

		return ($this->process_read ("notification_start_handler",
			"notification_end_handler", 'published'));
	} // }}}

	public function delete_item ($server, $node, $id) // {{{
	{
		$iq_id = time () . rand ();
		$this->ids['delete'] = 'retract' . $iq_id;

		$message = "<iq type='set' from='" . $this->jid . "' ";
		$message .= "to='" . $server . "' id='retract" . $iq_id . "'>";
		$message .= "<pubsub xmlns='http://jabber.org/protocol/pubsub'>";
		$message .= "<retract node='" . $node . "'><item id='";
		$message .= $id . "' /></retract></pubsub></iq>";

		if (! $this->socket->send ($message))
		{
			$this->last_error = __('Item deletion failure: ', 'xmpp-auth');
			$this->last_error .= $this->socket->last_error;
			$this->quit ();
			return FALSE;
		}

		return ($this->process_read ("item_deletion_start_handler",
			"item_deletion_end_handler", 'item_deleted'));
	} // }}}

	public function delete_node ($server, $node) // {{{
	{
		$iq_id = time () . rand ();
		$this->ids['delete'] = 'delete' . $iq_id;

		$message = "<iq type='set' from='" . $this->jid . "' ";
		$message .= "to='" . $server . "' id='delete" . $iq_id . "'>";
		$message .= "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>";
		$message .= "<delete node='" . $node . "' /></pubsub></iq>";

		if (! $this->socket->send ($message))
		{
			$this->last_error = __('Node deletion failure: ', 'xmpp-auth');
			$this->last_error .= $this->socket->last_error;
			$this->quit ();
			return FALSE;
		}

		return ($this->process_read ("node_deletion_start_handler",
			"node_deletion_end_handler", 'node_deleted'));
	} // }}}

	public function create_leaf ($server, $node) // {{{
	{
		if ($node == '')
		{
			$this->last_error = __('Empty node. No instant node supported.', 'xmpp-auth');
			return false;
		}

		$node_type = $this->node_type ($server, $node);

		// Workaround bug EJAB-672 of ejabberd.
		// This is the right behaviour but not working because of ejabberd bug.
		/*if ($node_type == 'leaf')
		{
			$this->last_error .= 'plouf!';
			return true;
		}
		elseif ($node_type == 'collection')
		{
			$this->last_error = __('This node already exists but is a collection node: "') . $node . '".';
			return false;
		} */ 
		// This is a flawed behaviour, due to the fact that all nodes are leaf node in ejabberd 2.0.1.
		if ($node_type != false)
			return true;
		// End of workaround.

		$subnode = $this->subnode ($node);

		if ($subnode == false || $this->create_collection ($server, $subnode))
		// XXX: there is no more semantics in node name,
		// so we should not use directory semantics in node name
		// (cf. section 12.13 of XEP-0060)
		// But for now, at least the ejabberd implementation requires this.
		{
			$iq_id = time () . rand ();
			$this->ids['leaf'] = 'create' . $iq_id;

			$message = "<iq type='set' from='" . $this->jid . "' ";
			$message .= "to='" . $server . "' id='create" . $iq_id . "'>";
			$message .= "<pubsub xmlns='http://jabber.org/protocol/pubsub'>";
			$message .= "<create node='" . $node . "'/><configure/>";
			$message .= "</pubsub></iq>";

			if (! $this->socket->send ($message))
			{
				$this->last_error = __('Leaf creation failure: ', 'xmpp-auth');
				$this->last_error .= $this->socket->last_error;
				$this->quit ();
				return FALSE;
			}

			return ($this->process_read ("leaf_creation_start_handler",
				"leaf_creation_end_handler", 'leaf_created'));
		}
		else
			return false;
	} // }}}

	public function create_collection ($server, $node) // {{{
	{
		if ($node == '')
		{
			$this->last_error = __('Empty node. No instant node supported.', 'xmpp-auth');
			return false;
		}

		$node_type = $this->node_type ($server, $node);

		// Workaround bug EJAB-672 of ejabberd.
		/*if ($node_type == 'collection') // || 'service' -> root!
			return true;
		elseif ($node_type == 'leaf')
		{
			$this->last_error = __('This node already exists but is a leaf node: "') . $node . '".';
			return false;
		}*/
		// This is a flawed behaviour, due to the fact that all nodes are leaf node in ejabberd 2.0.1.
		if ($node_type != false)
			return true;
		// End of workaround.

		$subnode = $this->subnode ($node);
		if ($subnode == false || $this->create_collection ($server, $subnode))
		// XXX: there is no more semantics in node name, so don't use directory semantics in node name
		// (cf. section 12.13 of XEP-0060)
		// But for now, at least the ejabberd implementation requires this.
		{
			$iq_id = time () . rand ();
			$this->ids['collection'] = 'create' . $iq_id;

			$message = "<iq type='set' from='" . $this->jid . "' ";
			$message .= "to='" . $server . "' id='create" . $iq_id . "'>";
			$message .= "<pubsub xmlns='http://jabber.org/protocol/pubsub'>";
			$message .= "<create node='" . $node . "'/><configure><x type='submit' xmlns='jabber:x:data'>";
			$message .= "<field var='FORM_TYPE' type='hidden'><value>http://jabber.org/protocol/pubsub#node_config</value></field>";
			$message .= "<field var='pubsub#node_type'><value>collection</value></field>";
			$message .= "</x></configure></pubsub></iq>";

			if (! $this->socket->send ($message))
			{
				$this->last_error = __('Collection node creation failure: ', 'xmpp-auth');
				$this->last_error .= $this->socket->last_error;
				$this->quit ();
				return FALSE;
			}

			return ($this->process_read ("collection_creation_start_handler",
				"collection_creation_end_handler", 'collection_created'));
		}
		else
			return false;
	} // }}}

/*
This function set a node as persistent, with at least $size as max_items.
*/
	public function configure_node ($server, $node, $size) // {{{
	{
		$this->conf['pubsub#max_items'] = $size; 
		$this->temp_node = $node;
		$this->temp_server = $server;

		$iq_id = time () . rand ();
		$this->ids['configure'] = 'configure' . $iq_id;

		$message = "<iq type='get' from='" . $this->jid . "' ";
		$message .= "to='" . $server . "' id='configure" . $iq_id . "'>";
		$message .= "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>";
		$message .= "<configure node='" . $node . "' />";
		$message .= "</pubsub></iq>";

		if (! $this->socket->send ($message))
		{
			$this->last_error = __('Node configuration failure: ', 'xmpp-auth');
			$this->last_error .= $this->socket->last_error;
			$this->quit ();
			return FALSE;
		}

		return ($this->process_read ("configure_node_start_handler",
					"configure_node_end_handler", 'configured'));
	} // }}}

	public function node_type ($server, $node) // return false if not existing, "leaf" and "collection" otherwise! // {{{
	{
		$iq_id = time () . rand ();
		$this->ids['node_info'] = 'info' . $iq_id;

		$query_info = "<iq type='get' from='" . $this->jid . "' to='" . $server . "' id='info" . $iq_id;
		$query_info .= "'><query xmlns='http://jabber.org/protocol/disco#info' node='";
		$query_info .= $node . "'/></iq>";

		if (! $this->socket->send ($query_info))
		{
			$this->last_error = __('Node information discovery failure: ', 'xmpp-auth');
			$this->last_error .= $this->socket->last_error;
			$this->quit ();
			return FALSE;
		}

		return ($this->process_read ("node_info_start_handler",
			"node_info_end_handler", 'node_type'));
	} // }}}

// this function returns "root1/root2" if you give it "root1/root2/node" and returns false if you give ''
	private function subnode ($node) // {{{
	{
		$pattern_root = '/^\/*$/';
		if (preg_match ($pattern_root, $node) == 1)
			return false;

		$pattern_first_level = '/^\/*[^\/]+\/*$/';
		if (preg_match ($pattern_first_level, $node) == 1)
			return false;

		$pattern = '/^(.+[^\/])(\/+[^\/]+\/*)$/';
		return (preg_replace ($pattern, '${1}', $node, 1));
	} // }}}
// Pubsub node configuration //

	private function configure_node_start_handler ($parser, $name, $attrs) // {{{
	{
		$changeable = array ('pubsub#deliver_payloads', 'pubsub#title', 'pubsub#max_items', 'pubsub#persist_items', 'pubsub#subscribe');
			
		$this->common_start_handler ($name);
		if ($name == 'jabber:client:iq' && $attrs['type'] == 'result' && $this->ids['configure'] == $attrs['id'])
		{
			unset ($this->ids['configure']);
			$this->flags['configuration_form'] = true;
		}
		elseif ($name == 'jabber:client:iq' && $attrs['type'] == 'error' && $this->ids['configure'] == $attrs['id'])
		{
			unset ($this->ids['configure']);
			$this->flags['configure_error'] = true;
		}
		elseif ($name == 'ERROR' && array_key_exists ('configure_error', $this->flags))
		{
			unset ($this->flags['configure_error']);
			$this->last_error = __('The request for configuration form returned an error of type "', 'xmpp-auth') . $attrs['type'] . '".';
			$this->flags['configured'] = false;
		}
		elseif ($name == 'FIELD' && in_array ($attrs['VAR'], $changeable))
		{
			$this->flags[$attrs['VAR']] = true;
		}
		elseif ($name == 'jabber:client:iq' && $attrs['id'] == $this->ids['configure2'])
		{
			unset ($this->ids['configure2']);
			$this->flags['configure_done'] = true;
		}

	} // }}}

	private function configure_node_end_handler ($parser, $name) // {{{
	{
		$this->common_end_handler ();
		if ($name == 'jabber:client:iq' && array_key_exists ('configuration_form', $this->flags))
		{
			unset ($this->flags['configuration_form']);
			// XXX: Now I will send my configuration...
			$iq_id = 'config' . time () . rand ();
			if (count ($this->conf) == 0)
			{
				// Nothing to change...
				// I just cancel
				$message = "<iq type='set' from='$this->jid' to='$this->temp_server' id='$iq_id'>"
					. "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>"
					. "<configure node='$this->temp_node'><x xmlns='jabber:x:data' type='cancel'/>"
					. "</configure></pubsub></iq>";
			}
			else
			{
				$message = "<iq type='set' from='$this->jid' to='$this->temp_server' id='$iq_id'>"
					. "<pubsub xmlns='http://jabber.org/protocol/pubsub#owner'>"
					. "<configure node='$this->temp_node'><x xmlns='jabber:x:data' type='submit'>";
				foreach ($this->conf as $var => $value)
				{
					$message .= "<field var='$var'><value>$value</value></field>";
				}
				$message .= "</x></configure></pubsub></iq>";
			}

			if (! $this->socket->send ($message))
			{
				$this->last_error = __('Node configuration failure: ', 'xmpp-auth');
				$this->last_error .= $this->socket->last_error;
				$this->quit ();
				$this->flags['configured'] = false;
				return;
			}
	
			$this->ids['configure2'] = $iq_id;

		}
		elseif ($name == 'jabber:client:iq' && array_key_exists ('configure_done', $this->flags))
		{
			unset ($this->flags['configure_done']);
			if ($attrs['type'] == 'result')
				$this->flags['configured'] = true;
			else
			{
				$this->flags['configured'] = false;
				$this->last_error = 'Failure to configure.';
			}
			return;
			// XXX: I don't check for the configuration result because a failure on configuration is not fatale.
			// Maybe one will be anyway able to publish. Ex: bug on ejabberd which prevents max_items from being more than 20:
			// https://support.process-one.net/browse/EJAB-819
			// Then when you publish, the older item is removed... but this is better than stop publishing the latter post.
		}
		elseif ($name == 'VALUE' && array_key_exists ('pubsub#persist_items', $this->flags))
		{
			// Items are persistent.
			unset ($this->flags['pubsub#persist_items']);
			if ($this->current_cdata != '1')
				$this->conf['pubsub#persist_items'] = "1";
		}
		elseif ($name == 'VALUE' && array_key_exists ('pubsub#subscribe', $this->flags))
		{
			// Users can subscribe.
			unset ($this->flags['pubsub#subscribe']);
			if ($this->current_cdata != '1')
				$this->conf['pubsub#subscribe'] = "1";
		}
		elseif ($name == 'VALUE' && array_key_exists ('pubsub#deliver_payloads', $this->flags))
		{
			// Payloads (= post's contents) is delivered.
			unset ($this->flags['pubsub#deliver_payloads']);
			if ($this->current_cdata != 'true')
				$this->conf['pubsub#deliver_payloads'] = "true";
		}
		elseif ($name == 'VALUE' && array_key_exists ('pubsub#title', $this->flags))
		{
			unset ($this->flags['pubsub#title']);
			// I change the title only if it is empty. This way, if the admin want to set manually a title (through a pubsub program),
			// then it won't be overriden by this plugin.
			if ($this->current_cdata == '')
				$this->conf['pubsub#title'] = "Notification node for: " . get_bloginfo ('name'); 
		}
		elseif ($name == 'VALUE' && array_key_exists ('pubsub#max_items', $this->flags))
		{
			unset ($this->flags['pubsub#max_items']);
			if ($this->current_cdata >= $this->conf['pubsub#max_items'])
				unset ($this->conf['pubsub#max_items']);
		}
	} // }}}

// Pubsub Notification //

	private function notification_start_handler ($parser, $name, $attrs) // {{{
	{
		if ($name == 'jabber:client:iq' && $attrs['type'] == 'result' && $this->ids['publish'] == $attrs['id'])
		{
			unset ($this->ids['publish']);
			$this->flags['published'] = true;
		}
		elseif ($name == 'jabber:client:iq' && $attrs['type'] == 'error' && $this->ids['publish'] == $attrs['id'])
		{
			unset ($this->ids['publish']);
			$this->flags['publish_error'] = true;
		}
		elseif ($name == 'ERROR' && array_key_exists ('publish_error', $this->flags))
		{
			unset ($this->flags['publish_error']);
			$this->last_error = __('Publication returned an error of type "', 'xmpp-auth') . $attrs['type'] . '".';
			$this->flags['published'] = false;
		}

		$this->common_start_handler ($name);
	} // }}}
	
	private function notification_end_handler ($parser, $name) // {{{
	{
		$this->common_end_handler ();
	} // }}}

// Item deletion //

	private function item_deletion_start_handler ($parser, $name, $attrs) // {{{
	{
		if ($name == 'jabber:client:iq' && $attrs['type'] == 'result' && $this->ids['delete'] == $attrs['id'])
		{
			unset ($this->ids['delete']);
			$this->flags['item_deletion_success'] = true;
		}
		elseif ($name == 'jabber:client:iq' && $attrs['type'] == 'error' && $this->ids['delete'] == $attrs['id'])
		{
			unset ($this->ids['delete']);
			$this->flags['item_deletion_error'] = true;
		}
		elseif ($name == 'ERROR' && array_key_exists ('item_deletion_error', $this->flags))
			$this->last_error = __('Item deletion returned an error of type "', 'xmpp-auth') . $attrs['type'] . '".';

		$this->common_start_handler ($name);
	} // }}}
	
	private function item_deletion_end_handler ($parser, $name) // {{{
	{
		$this->common_end_handler ();
		if ($name == 'jabber:client:iq' && array_key_exists ('item_deletion_error', $this->flags))
		{
			unset ($this->flags['item_deletion_error']);
			$this->flags['item_deleted'] = false;
		}
		elseif ($name == 'jabber:client:iq' && array_key_exists ('item_deletion_success', $this->flags))
		{
			unset ($this->flags['item_deletion_success']);
			$this->flags['item_deleted'] = true;
		}
	} // }}}

// Node deletion //

	private function node_deletion_start_handler ($parser, $name, $attrs) // {{{
	{
		if ($name == 'jabber:client:iq' && $attrs['type'] == 'result' && $this->ids['delete'] == $attrs['id'])
		{
			unset ($this->ids['delete']);
			$this->flags['node_deletion_success'] = true;
		}
		elseif ($name == 'jabber:client:iq' && $attrs['type'] == 'error' && $this->ids['delete'] == $attrs['id'])
		{
			unset ($this->ids['delete']);
			$this->flags['node_deletion_error'] = true;
		}
		elseif ($name == 'ERROR' && array_key_exists ('node_deletion_error', $this->flags))
			$this->last_error = __('Node deletion returned an error of type "', 'xmpp-auth') . $attrs['type'] . '".';

		$this->common_start_handler ($name);
	} // }}}
	
	private function node_deletion_end_handler ($parser, $name) // {{{
	{
		$this->common_end_handler ();
		if ($name == 'jabber:client:iq' && array_key_exists ('node_deletion_error', $this->flags))
		{
			unset ($this->flags['node_deletion_error']);
			$this->flags['node_deleted'] = false;
		}
		elseif ($name == 'jabber:client:iq' && array_key_exists ('node_deletion_success', $this->flags))
		{
			unset ($this->flags['node_deletion_success']);
			$this->flags['node_deleted'] = true;
		}
	} // }}}

// Leaf node creation //

	private function leaf_creation_start_handler ($parser, $name, $attrs) // {{{
	{
		if ($name == 'jabber:client:iq' && $attrs['type'] == 'result' && $this->ids['leaf'] == $attrs['id'])
		{
			unset ($this->ids['leaf']);
			$this->flags['leaf_creation_success'] = true;
		}
		elseif ($name == 'jabber:client:iq' && $attrs['type'] == 'error' && $this->ids['leaf'] == $attrs['id'])
		{
			unset ($this->ids['leaf']);
			$this->flags['leaf_creation_error'] = true;
		}
		elseif ($name == 'ERROR' && array_key_exists ('leaf_creation_error', $this->flags))
			$this->last_error = __('Leaf node creation returned an error of type "', 'xmpp-auth') . $attrs['type'] . '".';

		$this->common_start_handler ($name);
	} // }}}
	
	private function leaf_creation_end_handler ($parser, $name) // {{{
	{
		$this->common_end_handler ();
		if ($name == 'jabber:client:iq' && array_key_exists ('leaf_creation_error', $this->flags))
		{
			unset ($this->flags['leaf_creation_error']);
			$this->flags['leaf_created'] = false;
		}
		elseif ($name == 'jabber:client:iq' && array_key_exists ('leaf_creation_success', $this->flags))
		{
			unset ($this->flags['leaf_creation_success']);
			$this->flags['leaf_created'] = true;
		}
	} // }}}

// Collection node creation //

	private function collection_creation_start_handler ($parser, $name, $attrs) // {{{
	{
		if ($name == 'jabber:client:iq' && $attrs['type'] == 'result' && $this->ids['collection'] == $attrs['id'])
		{
			unset ($this->ids['collection']);
			$this->flags['collection_creation_success'] = true;
		}
		elseif ($name == 'jabber:client:iq' && $attrs['type'] == 'error' && $this->ids['collection'] == $attrs['id'])
		{
			unset ($this->ids['collection']);
			$this->flags['collection_creation_error'] = true;
		}
		elseif ($name == 'ERROR' && array_key_exists ('collection_creation_error', $this->flags))
			$this->last_error = __('Collection node creation returned an error of type "', 'xmpp-auth') . $attrs['type'] . '".';

		$this->common_start_handler ($name);
	} // }}}
	
	private function collection_creation_end_handler ($parser, $name) // {{{
	{
		$this->common_end_handler ();
		if ($name == 'jabber:client:iq' && array_key_exists ('collection_creation_error', $this->flags))
		{
			unset ($this->flags['collection_creation_error']);
			$this->flags['collection_created'] = false;
		}
		elseif ($name == 'jabber:client:iq' && array_key_exists ('collection_creation_success', $this->flags))
		{
			unset ($this->flags['collection_creation_success']);
			$this->flags['collection_created'] = true;
		}
	} // }}}

// Node information discovery //

	private function node_info_start_handler ($parser, $name, $attrs) // {{{
	{
		if ($name == 'jabber:client:iq' && $attrs['type'] == 'result' && $this->ids['node_info'] == $attrs['id'])
		{
			unset ($this->ids['node_info']);
			$this->flags['node_info_success'] = true;
		}
		elseif ($name == 'IDENTITY' && array_key_exists ('node_info_success', $this->flags))
			$this->flags['node_identity'] = $attrs['type'];
		elseif ($name == 'jabber:client:iq' && $attrs['type'] == 'error' && $this->ids['node_info'] == $attrs['id'])
		{
			unset ($this->ids['node_info']);
			$this->flags['node_info_error'] = true;
		}
		elseif ($name == 'ERROR' && array_key_exists ('node_info_error', $this->flags))
			$this->last_error = __('Node information discovery returned an error of type "', 'xmpp-auth') . $attrs['type'] . '".';

		$this->common_start_handler ($name);
	} // }}}
	
	private function node_info_end_handler ($parser, $name) // {{{
	{
		if ($name == 'jabber:client:iq' && array_key_exists ('node_info_error', $this->flags))
		{
			unset ($this->flags['node_info_error']);
			$this->flags['node_type'] = false;
		}
		elseif ($name == 'jabber:client:iq' && array_key_exists ('node_info_success', $this->flags))
		{
			unset ($this->flags['node_info_success']);
			if (array_key_exists ('node_identity', $this->flags))
			{
				$this->flags['node_type'] = $this->flags['node_identity'];
				unset ($this->flags['node_identity']);
			}
			else
				$this->flags['node_type'] = false;
		}

		$this->common_end_handler ();
	} // }}}
} // }}}
endif;

?>

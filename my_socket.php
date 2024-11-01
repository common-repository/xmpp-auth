<?php
/************ XMPP-Auth ***************\
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
\******************************************/

// This simplistic class creates a TCP/IPV4/6 socket in non-blocking mode.
if (!class_exists('my_socket')):
class my_socket // {{{
{
	public $server = NULL;
	public $port = NULL;
	public $last_error = NULL;

	private $socket = NULL;

	/*function __construct ($server, $port)
    {
        $this->server = $server;
        $this->port = $port;
    }*/

  function connect() // {{{
  {
    $_socket = FALSE;
    /* In IPV-6 format, we must enclose in square bracket. */
    if (preg_match('/^([0-9a-fA-F]{0,4}:){1,7}:[0-9a-fA-F]{0,4}$/', $this->server))
      @$_socket = stream_socket_client("tcp://[" . $this->server . "]:" . $this->port, $errno, $errstr, 2);
    else
      @$_socket = stream_socket_client("tcp://" . $this->server . ":" . $this->port, $errno, $errstr, 2);
    if ($_socket === FALSE)
    {
      $this->last_error = __('Connection initiation failed.', 'xmpp-auth') . '<br />';
      $this->last_error .= "$errstr ($errno)";
      @fclose ($_socket);
    }
    if ($_socket === FALSE)
      return FALSE;

    if (!stream_set_blocking($_socket, 0))
    {
      $this->last_error = __('The socket could not be set in non-blocking mode.', 'xmpp-auth');
      @fclose ($_socket);
      return FALSE;
    }

    $this->socket = $_socket;
    return TRUE;
  } // }}}

    /**
     * @return string|bool string data read from the socket on success, FALSE on failure.
     */
	function read() // {{{
	{
		if ($this->socket != NULL)
		{
			// I need to set a timeout if I don't want to wait too long when it does not receive 8192 bytes.
			stream_set_timeout($this->socket, 1, 0); // 1.0 seconds.
			$received_data = fread($this->socket, 8192);
			// I read by block. Non-blocking mode does not seem to work in encrypted data...
			if (strlen($received_data) != 0)
				jabber_feed_log ("Received data: \n" . $received_data);
			return $received_data;
		}
		else
		{
			$this->last_error = __('Trying to read in a null socket.', 'xmpp-auth');
			jabber_feed_log ($this->last_error);
			return FALSE;
		}
	} // }}}

    /**
     * @return bool TRUE on success, FALSE on failure.
     */
	function send($data) // {{{
	{
		if ($this->socket == NULL)
		{
			$this->last_error = __('Trying to write in a null socket.', 'xmpp-auth');
			jabber_feed_log ($this->last_error);
			return FALSE;
		}

		$data_length = strlen($data);
		$bytes_sent = 0;

		$timeout = 2;
		$last_update = time();
		while ($bytes_sent < $data_length)
		{
			$new_bytes_sent = fwrite($this->socket, substr($data, $bytes_sent));
			/* XXX: the sending over socket returns the number of *bytes*...
				But substr writes about start *character*. This is not an issue *currently* because "Before PHP 6, a character is the same as a byte".
				Yet in the future (PHP 6 so?), it can make an error if ever the $data is not fully sent at once, and it is stopped in the middle of a character (UTF-8 for instance, most common now). Of course, even in PHP6, this will be a rare case where we are pretty unlucky. Still it would be possible. 
                -> I am not sure why I wrote this. Did I see this information somewhere? I can't see this about substr. */
			if ($new_bytes_sent === FALSE)
			{
				$this->last_error = __('Data could not be sent.', 'xmpp-auth');
				jabber_feed_log ("Socket error while sending: \n" . $data);
				return FALSE;
			}
			elseif ($new_bytes_sent > 0)
			{
                // For more than 2 seconds, you could not send data.
				$bytes_sent += $new_bytes_sent;
				$last_update = time();
				continue;
			}
			elseif (time () - $last_update > $timeout)
			{
				$this->last_error = __('Timeout during a data transfer', 'xmpp-auth');
				jabber_feed_log ("Timeout while sending: \n" . $data);
				return FALSE;
			}
		}
		jabber_feed_log ("Sent: \n" . $data);
		return TRUE;
	} // }}}

    /**
     * @return bool TRUE.
     */
	function close() // {{{
	{
		if ($this->socket == NULL)
			return TRUE;
		
		fclose($this->socket);
		return TRUE;
	} // }}}

    /**
     * @return bool TRUE on success, FALSE on failure.
     */
	function encrypt() // {{{
	{
		if ($this->socket == NULL)
		{
			$this->last_error = __('Trying to encrypt a null socket.', 'xmpp-auth');
			return FALSE;
		}

        // stream_socket_enable_crypto is likely to fail in non-blocking mode.
		stream_set_blocking($this->socket, 1);

		$stream_options = array('ssl' =>
			array('verify_peer' => true,
			'capath' => dirname(__FILE__) . '/certs/'));
    set_error_handler(function($errno, $errstr, $errfile, $errline, array $errcontext)
        {
          /* error was suppressed with the @-operator. */
          if (0 === error_reporting())
          {
            return
            false;
          }

          throw new ErrorException($errstr, 0, $errno, $errfile, $errline);
        });

    try
    {
      if (stream_context_set_option($this->socket, $stream_options)
          && stream_socket_enable_crypto($this->socket, TRUE, STREAM_CRYPTO_METHOD_SSLv23_CLIENT))
      {
        // XXX: why does # STREAM_CRYPTO_METHOD_TLS_CLIENT does not work in Gmail?!
        // Probably feature not implemented.
        // So as a special workaround, I try SSL instead...
        // It seems to work on other servers (jabber.org works with both TLS and SSL).
        if (!stream_set_blocking($this->socket, 0))
        {
          $this->last_error = __('The socket could not be set in non-blocking mode after encryption.', 'xmpp-auth');
          fclose($this->socket);
          return FALSE;
        }
        return TRUE;
      }
      else
      {
        // If neither TLS not SSL worked...
        $this->last_error = __('TLS negotiation failed.', 'xmpp-auth');
        return FALSE;
      }
    }
    catch (ErrorException $e)
    {
      if (strstr($e->getMessage(), 'certificate verify failed'))
      {
        /* Known error, I set a custom error message. */
        $this->last_error = __('certificate verification failed.');
        $this->last_error .= "\n" . __('Contact the developer with details on your IM domain name for plugin update:')
          . "\n" . ' https://wordpress.org/plugins/xmpp-auth/';
      }
      else
      {
        $this->last_error = $e->getMessage();
      }
      fclose($this->socket);
      return FALSE;
    }

		/* There is 2 wrong returns: either FALSE, which means negotiation failed,
			or 0 if there isn't enough data and you should try again (only for non-blocking sockets).
			As this is a bot, and there is no human interaction, the second case is also wrong for us, so I don't distinguate them (but maybe would it be better for debugging?)...
			*/
	} // }}}

} // }}}
endif;

?>

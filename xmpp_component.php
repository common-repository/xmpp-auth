<?php
/*
{{{
    XMPP-Auth -- A Wordpress plugin to authenticate via XMPP.
    Copyright 2011 Jehan Hysseo

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

if (!class_exists('xmpp_component')):

require_once(dirname(__FILE__) . '/xmpp_stream.php');
class xmpp_component extends xmpp_stream
{
    private $name = '';
    private $secret = '';

	function __construct ($name, $secret, $server, $port) // {{{
	{
		$this->name = $name;
		$this->secret = $secret;
		$this->server = array($server);
		$this->port = array($port);
	} // }}}

	public function log () // {{{
	{
		if (!$this->logged && $this->connect() && $this->authenticate())
			$this->logged = true;
		
		return $this->logged;
	} // }}}

	private function authenticate() // {{{
	{
        // We could just use the bare JID, but as I will create many streams for the same component,
        // I need to be able to separate them.
		$resource = time () . rand (); // Is it random enough? Probably for such use...

		$stream_begin = "<stream:stream xmlns='jabber:component:accept'
			xmlns:stream='http://etherx.jabber.org/streams'
			to='" . $this->name . '/' . $resource .
            "' version='1.0'>";

		if (! $this->socket->send ($stream_begin))
		{
			$this->last_error = __('Stream initiate failure: ', 'xmpp-auth');
			$this->last_error .= $this->socket->last_error;
			$this->quit ();
			return false;
		}

		return ($this->process_read ("authentication_start_handler",
			"authentication_end_handler", 'authenticated'));
	} // }}}

	private function authentication_start_handler($parser, $name, $attrs) // {{{
	{
		if ($name == 'STREAM:STREAM')
		{
            $this->jid = $attrs['FROM'];
            $contents = $attrs['ID'] . $this->secret;
            $contents = sha1($contents, false); // must be in hex format.
            $contents = strtolower($contents);
			$handshake = '<handshake>' . $contents . '</handshake>';
			if (!$this->socket->send($handshake))
			{
				$this->last_error = __('Authentication failure: ', 'xmpp-auth');
				$this->last_error .= $_socket->last_error;
				$this->flags['authenticated'] = false;
			}
            else
                $this->flags['handshake_sent'] = true;
			return;
		}
		$this->common_start_handler ($name);
	} // }}}

	private function authentication_end_handler ($parser, $name) // {{{
	{
		$this->common_end_handler ();
		if ($name == 'HANDSHAKE' && isset($this->flags['handshake_sent']))
		{
			$this->flags['authenticated'] = true;
			return;
		}
		elseif ($name == 'STREAM:ERROR' || $name == 'STREAM:STREAM')
		{
			$this->socket->send ('</stream:stream>');
			$this->last_error = __('Authentication failure: handshake failed.', 'xmpp-auth');
			$this->flags['authenticated'] = false;
			return;
		}
	} // }}}

}
endif;

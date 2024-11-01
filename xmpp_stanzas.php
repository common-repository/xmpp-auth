<?php
/*
    Copyright (C) 2011 Jehan Pagès (IM: xmpp:hysseo@zemarmot.net)
    [ No email contact, but you can send message through Instant Messaging,
    and you are not force to add my presence for this.
    You can also just send a normal message. I try to answer every message. ]

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program (file LICENSE at the root of the source archive). 
    If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * Helper library to generate various kind of common stanzas.
 */

function http_auth($from, $to, $http_url, $http_method, &$transaction_id,
                   &$thread, $readable_message = NULL,
                   $transaction_id_label = NULL) // {{{
{
    $http_method = strtoupper($http_method);
    if (!in_array($http_method, array('GET', 'POST', 'PUT', 'DELETE')))
        return false;

    // Gajim has issues with tags, even when they have been transformed into entities!
    $transaction_id = strip_tags($transaction_id);
    // I had some issues which Gajim which was stripping newlines! Though it is definitely a bug in Gajim,
    // for now I bypass it. TODO: check latest version of Gajim.
    $transaction_id = preg_replace('/\r\n|\r|\n/', ' ', $transaction_id);
    // I don't save the transaction ID, XML-formatted.
    $_transaction_id = htmlspecialchars($transaction_id, ENT_QUOTES, "UTF-8");

    if (is_null($transaction_id_label))
      $transaction_id_label = __('Transaction ID', 'xmpp-auth');
    if (is_null($readable_message))
        $readable_message = __('Someone (maybe you) has requested access to the following web page:', 'xmpp-auth') . "\n" . $http_url;
    $readable_message .= "\n"
                         . sprintf (__('If you confirm you made this request, send the "%s" which was given to you.', 'xmpp-auth'),
                                    $transaction_id_label);
    $readable_message .= "\n" . __('Otherwise answer "NO".', 'xmpp-auth');

    $message = "<message type='normal' from='" . $from . "' ";
    $message .= "to='" . $to . "' id='" . $thread . "'>";
    $message .= "<thread>" . $thread . "</thread>";
    $message .= "<body>" . $readable_message . "</body>";
    $message .= "<confirm xmlns='http://jabber.org/protocol/http-auth'  id='$_transaction_id' method='$http_method' url='$http_url'/></message>";

    return $message;
} // }}}

/**
 * XEP-0084.
 */
function subscribe_avatar($params)
{
}

?>

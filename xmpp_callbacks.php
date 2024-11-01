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

function http_auth_cb($stream, $stanza, $params, &$termination)
{
    require_once(dirname(__FILE__) . '/xmpp_utils.php');

    if ($stanza->localName == 'message' && $stanza->namespaceURI == 'jabber:client'
        && xmpp_bare_jid($stanza->getAttributeNS(NULL, 'from')) == xmpp_bare_jid($params['from'])
        && xmpp_bare_jid($stanza->getAttributeNS(NULL, 'to')) == xmpp_bare_jid($stream->jid))
    {
        //$xpath = new DOMXPath($this->dom);
        $children = $stanza->childNodes;
        $length = $children->length;
        if ($length == 0)
            return FALSE;
        $thread = FALSE;
        for ($i = 0; $i < $length; $i++)
        {
            $child = $children->item($i);
            if ($child->nodeType == XML_ELEMENT_NODE
                && $child->localName == 'thread'
                && $child->namespaceURI == 'jabber:client'
                && $child->nodeValue == $params['thread'])
            {
                $thread = TRUE;
                break;
            }
        }
        /*if (!$thread)
            return FALSE;*/

        // If the <confirm/> is set, it must mirror the original.
        $confirm = false;
        if ($thread)
        {
          for ($i = 0; $i < $length; $i++)
          {
            $child = $children->item($i);
            if (!($child->nodeType == XML_ELEMENT_NODE
                  && $child->localName == 'confirm'
                  && $child->namespaceURI == 'http://jabber.org/protocol/http-auth'))
              continue;

            if ($child->getAttributeNS(NULL, 'id') == $params['transaction_id']
                && $child->getAttributeNS(NULL, 'method') == $params['method']
                && $child->getAttributeNS(NULL, 'url') == $params['url'])
              $confirm = true;
            else
              return FALSE; // something is wrong with this <confirm/>

            break;
          }
        }

        if ($stanza->getAttributeNS(NULL, 'type') == 'error')
        {
            $termination = FALSE;
            // TODO: I am supposed to check the error too. But is it really necessary?
            return TRUE;
        }
        else
        {
            if ($confirm)
                $termination = TRUE;
            else
            {
                $has_body = FALSE;
                for ($i = 0; $i < $length; $i++)
                {
                    $child = $children->item($i);
                    if (!($child->nodeType == XML_ELEMENT_NODE
                        && $child->localName == 'body'
                        && $child->namespaceURI == 'jabber:client'))
                        continue;

                    $has_body = TRUE;
                    if (trim($child->nodeValue) == $params['transaction_id'])
                        $termination = TRUE;
                    else
                        $termination = FALSE;
                    break;
                }
                if (!$has_body)
                    $termination = FALSE;
            }
        }
    }

    return FALSE;
}

?>

<?php
/*  Copyright 2008;2011 Jehan Hysseo

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
*/

if (!function_exists('imauth_valid_jid')):
// Validate  a JID
function imauth_valid_jid($jid)
{
	// If the PECL idn lib is installed:
	// - I check the localpart against the nodeprep profile;
	// - the domainpart against
	// either "IP-literal / IPv4address" (rfc-3986) as a first-match-wins,
	// or the nameprep profile of stringprep,
	// as described in RFC-6122.
	$jid_pattern = '#[^@]+@[^/]+(/.+)?#';
	if (preg_match($jid_pattern, $jid))
		return true;
	else
		return false;

	// TODO: add libidn support: http://pecl.php.net/package/idn/0.2.0
	//include_once("php_idn.h");
	//dl('idn.so');
	//if (!extension_loaded("idn")) print "skip";
	//echo idn_to_ascii(utf8_encode("pag�s"));
}
endif;

if (!function_exists('xmpp_bare_jid'))
{
	function xmpp_bare_jid($jid)
	{
		$jid_pattern = '#^([^@]+@[^/]+)(/.+)?$#';
		if (preg_match($jid_pattern, $jid, $matches))
			return $matches[1];
		else
			return false;
	}
}

if (!function_exists('fixxhtml'))
{
	function fixxhtml ($badxhtml) // {{{
	{
		if (function_exists ("tidy_repair_string"))
		{
			$config = array(
					'bare' => TRUE,
					'doctype' => "omit",
					'drop-empty-paras' => TRUE,
					'drop-font-tags' => TRUE,
					'drop-proprietary-attributes' => TRUE,
					'fix-backslash' => TRUE,
					'hide-comments' => TRUE,
					'fix-backslash' => TRUE,
					'fix-uri' => TRUE,
					'logical-emphasis' => TRUE,
					'numeric-entities' => TRUE, // I don't want html entities!
					'output-xhtml' => TRUE,
					'show-body-only' => TRUE,
					'uppercase-attributes' => FALSE,
					'uppercase-tags' => FALSE,
					// Pretty print stuff. Not really useful, just not to have too big lines.
					'wrap' => 200);
			//return tidy_repair_string ($badxhtml, $config, 'utf8');
			$ret = tidy_repair_string ($badxhtml, $config, 'utf8');
			return $ret;
		}
		else
			return false;
		// TODO: make a manual (but probably less powerful) method for tidy library is not installed?

		//$tidy = new tidy;
		//$tidy->parseString($xhtml, $config, 'utf8');
		//$tidy->cleanRepair();
	} // }}}
}

// these 2 variables should not be used elsewhere than in "xhtml2xhtmlim" or "xhtml2bare"...
// I could not find any other way to use a common data to all handler functions (for XML parsing)
// than make global variables...
// Is there any nicer workaround?
$xhtmlim = "";
$stack = array ();

// This function transforms $xhtml, which is a normal xhtml content in the corresponding xhtml-im content.
// It supports currently only the core module of XEP-0071.
// cf. http://www.xmpp.org/extensions/xep-0071.html
// This first version does not fix badly html originally + do not remove illegal characters.
// http://openweb.eu.org/articles/xhtml_une_heure/
if (!function_exists('xhtml2xhtmlim'))
{
	function xhtml2xhtmlim ($xhtml) // {{{
	{
		global $xhtmlim;
		$xhtml = fixxhtml ($xhtml);

		if ($xhtml == false)
			// no need to continue if I cannot even check xhtml integrity...
			return false;

		// From now on, I am supposing the xhtml is compliant.
		// Or else it means "tidy" is bugged because I use the tidy package for this.
		//$xhtmlim = "";
		//$stack = array ();

		if (!function_exists ("start_handler"))
		{
			function start_handler ($parser, $name, $attrs) // {{{
			{
				global $xhtmlim;
				global $stack;
				// I don't have to ignore head, html and title elements in the context of this plugin,
				// as they are anyway (normally at least) not present in a post content.
				// TODO: section 7.2 -> only br, p and span? What about b, em and hX especially?!!
				// Section 7.2: br, and p only for now.
				if ($name == "br")
				{
					// no need to push on the stack as "normally" if tidy made well its job, it will close immediately.
					// But anyway, no risk to do it...
					array_push ($stack, false);
					$xhtmlim .= "<br/>";
				}
				elseif ($name == "p")
				{
					array_push ($stack, true);
					$xhtmlim .= "<p>";
				}
				elseif ($name == "strong" || $name == "em" || preg_match ("/^h[1-6]$/", $name) > 0)
				{
					array_push ($stack, true);
					$xhtmlim .= '<' . $name . '>';
				}
				// Section 7.3: only a with mandatory "href" and recommended "type".
				elseif ($name == "a")
				{
					if (array_key_exists ('href', $attrs))
					{
						array_push ($stack, true);
						$xhtmlim .= '<a href="' . $attrs['href'];
						if (array_key_exists ('type', $attrs))
							$xhtmlim .= '" type="' . $attrs['type'] . '">';
						else
							$xhtmlim .= '">"';
					}
					else
						array_push ($stack, false);
				}
				// section 7.4: only ol, ul and li recommended (what about "title" and accesskey for accessibility?!).
				// And why not def list? This is just done for IM but XMPP is more than just IM.
				elseif ($name == "ol" || $name == "ul" || $name == "li")
				{
					array_push ($stack, true);
					$xhtmlim .= '<' . $name . '>';
				}
				elseif  ($name == "img")
				{
					if (array_key_exists ('src', $attrs) && array_key_exists ('alt', $attrs))
					{
						array_push ($stack, true);
						$xhtmlim .= '<img src="' . $attrs['src'] . '" alt="' . $attrs['alt'];
						if (array_key_exists ('height', $attrs))
							$xhtmlim .= '" height="' . $attrs['height'];
						if (array_key_exists ('width', $attrs))
							$xhtmlim .= '" width="' . $attrs['width'];
						$xhtmlim .= '" />';
					}
					else
						array_push ($stack, false);
				}
				else
					array_push ($stack, false);
			} // }}}
		}

		if (!function_exists ("end_handler"))
		{
			function end_handler ($parser, $name) // {{{
			{
				global $xhtmlim;
				global $stack;
				$last_element_has_been_displayed = array_pop ($stack);
				if ($last_element_has_been_displayed)
					$xhtmlim .= "</" . $name . ">";
			} // }}}
		}

		if (!function_exists ("cdata_handler"))
		{
			function cdata_handler ($parser, $data) // {{{
			{
				global $xhtmlim;
				$xhtmlim .= $data;
			} // }}}
		}

		$xml_parser = xml_parser_create("UTF-8");
		xml_parser_set_option ($xml_parser, XML_OPTION_CASE_FOLDING, 0);
		xml_set_element_handler ($xml_parser, "start_handler", "end_handler");
		xml_set_character_data_handler ($xml_parser, "cdata_handler");

		$parse_status = xml_parse ($xml_parser, "<html>$xhtml</html>", TRUE);
		xml_parser_free ($xml_parser);

		$ret_value = "<html xmlns='http://jabber.org/protocol/xhtml-im'><body xmlns='http://www.w3.org/1999/xhtml'>" . $xhtmlim . '</body></html>';
		$xhtmlim = "";
		$stack = array ();

		if ($parse_status == XML_STATUS_ERROR)
			return FALSE;

		//$xhtmlim = html_entity_decode ($xhtml, ENT_QUOTES, "UTF-8");
		// maybe should I use char-encoding and input-encoding options of tidy instead?
		// '&' and '<' are the only characters which must be transformed in &amp; and &lt;.
		// The rest is utf-8, so I let them in their equivalent utf-8 (by html_entity_decode).
		// TODO: test &oelig;
		// numeric entities?!

		return $ret_value;
	} // }}}
}

if (!function_exists('xhtml2bare'))
{
	function xhtml2bare ($xhtml) // {{{ Todo: shouldn't I rather use again the xml parser?!!
	{
		global $xhtmlim;
		global $stack;
		$fixed_html = fixxhtml ($xhtml);

		// TODO: there must be a guard to prevent from redefine this, for instance function_exists).
		if (!function_exists ("start_bare_handler"))
		{
			function start_bare_handler ($parser, $name, $attrs) // {{{
			{
				global $xhtmlim;
				global $stack;
				if ($name == "br")
				{
					array_push ($stack, false);
					$xhtmlim .= "\n";
				}
				elseif ($name == "p")
				{
					$xhtmlim .= "\n\t";
					array_push ($stack, false);
				}
				elseif (preg_match ("/^h[1-6]$/", $name) > 0)
				{
					$xhtmlim .= "\n";
					$value = intval ($name[1]);
					for ($i = 0; $i < $value; $i++)
						$xhtmlim .= "=";
					array_push ($stack, false);
				}	
				elseif ($name == "strong" || $name == "em")
					array_push ($stack, false);
				elseif ($name == "a")
				{
					if (array_key_exists ('href', $attrs))
					{
						array_push ($stack, $attrs['href']); // shouldn't I keep the "href" value and write it at the end?!!
						//$xhtmlim .= '<a href="' . $attrs['href'];
						//if (array_key_exists ('type', $attrs))
						//	$xhtmlim .= '" type="' . $attrs['type'] . '">';
						//else
						//	$xhtmlim .= '">"';
					}
					else
						array_push ($stack, false);
				}
				// And why not def list? This is just done for IM but XMPP is more than just IM.
				elseif ($name == "ol")
				{
					array_push ($stack, 1);
					$xhtmlim .= "\n";
				}
				elseif ($name == "ul")
				{
					array_push ($stack, false);
					$xhtmlim .= "\n";
				}
				elseif ($name == "li")
				{
					//$xhtmlim .= "-"; // should'nt I differentiate ol from ul?!! #1#
					$num = array_pop ($stack);
					if ($num == false)
					{
						$xhtmlim .= "\t&#8658; ";
						array_push ($stack, false);
						array_push ($stack, false);
					}
					else
					{
						$xhtmlim .= "\t#" . strval ($num) . "# ";
						array_push ($stack, $num + 1);
						array_push ($stack, false);
					}
				}	
				elseif ($name == "blockquote" || $name == "code")
				{
					array_push ($stack, false);
					$xhtmlim .= "\n«\n";
				}
				else
					array_push ($stack, false);
			} // }}}
		}

		if (!function_exists ("end_bare_handler"))
		{
			function end_bare_handler ($parser, $name) // {{{
			{
				global $xhtmlim;
				global $stack;
				if ($name == "br" || $name == "strong" || $name == "em")
					array_pop ($stack);
				elseif ($name == "p")
				{
					$xhtmlim .= "\n";
					array_pop ($stack);
				}
				elseif (preg_match ("/^h[1-6]$/", $name) > 0)
				{
					array_pop ($stack);
					$value = intval ($name[1]);
					for ($i = 0; $i < $value; $i++)
						$xhtmlim .= "=";
					$xhtmlim .= "\n";
				}
				elseif ($name == "a")
				{
					$link = array_pop ($stack);
					if ($link != false)
						$xhtmlim .= " [ $link ] ";
				}
				elseif ($name == "ol" || $name == "ul" || $name == "li")
				{
					$link = array_pop ($stack);
					$xhtmlim .= "\n";
				}
				elseif ($name == "blockquote" || $name == "code")
				{
					$xhtmlim .= "\n»\n";
					array_pop ($stack);
				}
				else
					array_pop ($stack);

				//$must_go_to_line = array_pop ($stack);
				//if ($must_go_to_line == true)
				//	$xhtmlim .= "\n";
				//elseif ($must_go_to_line == false)
				//	;
				//else
				//	$xhtmlim .= " [ " . $must_go_to_line . " ] ";
			} // }}}
		}

		if (!function_exists ("cdata_bare_handler"))
		{
			function cdata_bare_handler ($parser, $data) // {{{
			{
				global $xhtmlim;
				$xhtmlim .= $data;
			} // }}}
		}

		if ($fixed_html != false)
		{
			$xml_parser = xml_parser_create("UTF-8");
			xml_set_element_handler ($xml_parser, "start_bare_handler", "end_bare_handler");
			xml_set_character_data_handler ($xml_parser, "cdata_bare_handler");
			xml_parser_set_option ($xml_parser, XML_OPTION_CASE_FOLDING, 0);

			$parse_status = xml_parse ($xml_parser, "<html>$xhtml</html>", TRUE);
			xml_parser_free ($xml_parser);

			$pattern[0] = '/\n(\s*\n)+/';
			$replacement[0] = "\n\n"; // no more than 2 white lines and ending white spaces (\t for <li>) kept.

			$pattern[1] = "/\t+/";
			$replacement[1] = "\t"; // but no more than one tab!

			$bare = preg_replace ($pattern, $replacement, $xhtmlim);
			$xhtmlim = "";
			$stack = array ();

			if ($parse_status != XML_STATUS_ERROR)
				return $bare; // all went OK!
		}
		// I am here if I could not fix the xhtml (most likely tidy is not installed),
		// or if the parse failed for some reason... So I will return with a more rudimentary method.

		// note: 'n&oelig;uds de publication' does not work. It must be utf8. Is it normal?
		$pattern[0] = "/( |\t)+/";
		$replacement[0] = ' ';

		$pattern[1] = '/<p(\s[^>]*)?>((.|\n)*)<\/p\s*>/U';
		$replacement[1] = "\t" .'${2}' . "\n";

		$pattern[3] = '/<span(\s[^>]*)?>((.|\n)*)<\/span\s*>/U';
		$replacement[3] = '${2}';

		$pattern[4] = '/<a\s+[^>]*href=(\'|")([^\'"]*)\1[^>]*>((.|\n)*)<\/a\s*>/U'; // here is it possible ' or " in a url?
		$replacement[4] = '${3} [ ${1} ]';

		$pattern[6] = '/<li(\s[^>]*)?>((.|\n)*)<\/li\s*>/U';
		$replacement[6] = "\n\t&#8658; " . '${2}';

		// I simply remove all emphasing tags: strong, b, em, i.

		$pattern[10] = '/<b(\s[^>]*)?>(.*)<\/b\s*>/U';
		$replacement[10] = '${2}';

		$pattern[11] = '/<em(\s[^>]*)?>(.*)<\/em\s*>/U';
		$replacement[11] = '${2}';

		$pattern[12] = '/<strong(\s[^>]*)?>(.*)<\/strong\s*>/U';
		$replacement[12] = '${2}';

		$pattern[13] = '/<i(\s[^>]*)?>(.*)<\/i\s*>/U';
		$replacement[13] = '${2}';

		$pattern[14] = '/<blockquote(\s[^>]*)?>((.|\n)*)<\/blockquote\s*>/U';
		$replacement[14] = "\n«\n" . '${2}' . "\n»\n";

		$pattern[15] = '/<code(\s[^>]*)?>((.|\n)*)<\/code\s*>/U';
		$replacement[15] = "\n«\n" . '${2}' . "\n»\n";

		$pattern[7] = '/<(ul|ol)(\s[^>]*)?>((.|\n)*)<\/\1\s*>/U';
		$replacement[7] = '${3}' . "\n";
		// for ol, I may replace li by #somerandomnumber# then count the size and finally replace by X/.

		//$pattern[16] = '/\n(\s|\n)+/';
		//$replacement[16] = "\n";

		$pattern[2] = '/<div(\s[^>]*)?>(.*)<\/div\s*>/U';
		$replacement[2] = '${2}' . "\n";

		$pattern[5] = '/<br[^>]*>/';
		$replacement[5] = "\n";

		$pattern[18] = '/<(h[1-6])[^>]*>(.*)<\/\1\s*>/U';
		$replacement[18] = "\n=== " . '${2}' . " ===\n";

		// I remove all the other tags, but not their content.
		$pattern[8] = '/<([^\s>]*)[^>]*>((.|\n)*)<\/\1>/U';
		$replacement[8] = '${2}';

		$pattern[9] = '/<[^>]*>/';
		$replacement[9] = '';

		$pattern[17] = '/\n(\s*\n)+/';
		$replacement[17] = "\n\n"; // no more than 2 blank lines at once... And I keep the white characters after the last one (for \t of <li>).

		$pattern[19] = "/\t+/";
		$replacement[19] = "\t"; // but no more than one tab!

		$bare = html_entity_decode ((preg_replace ($pattern, $replacement, $xhtml)), ENT_NOQUOTES, "UTF-8");

		// normalement, une fois le html d�cod�, je retire < et &, non?
		// http://www.journaldunet.com/developpeur/tutoriel/xml/041027-xml-caracteres-speciaux.shtml

		$pattern2[1] = '/&/';
		$replacement2[1] = '&amp;';

		$pattern2[0] = '/</';
		$replacement2[0] = '&lt;';

		return (preg_replace ($pattern2, $replacement2, $bare));
	} // }}}
}


/*
 * Add the new entry $entry in the logs, with the current date.
 */
// See this: interesting for making logs, then display it!
// http://fr2.php.net/manual/en/errorfunc.examples.php
if (!function_exists('jabber_feed_log'))
{
	function jabber_feed_log ($entry) // {{{
	{
		// XXX: uncomment this to log errors for debugging.
		$date = date ('Y-m-d\TH:i:s+Z'); 

		$error_msg = '**** ' . $date . " ****\n\n" . $entry . "\n\n";
		error_log ($error_msg, 3, '/tmp/imauth_errors.log');
	} // }}}
}

/*
 * What about a future feature of sending a message through Jabber to an admin JID?
 * Use the Jabber item in the user profile (exists already) and send to any guy with role administrator.
 * $user_info = get_userdata(1); 
 * http://codex.wordpress.org/Function_Reference/get_userdata
 TODO: -> look in the db...
 */
if (!function_exists('jabber_feed_error_send'))
{
	function jabber_feed_error_send ($msg)
	{
	}
}

?>

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
 * A DNS helper I'd like to see integrated in PHP core someday.
 */

if (!function_exists('dns_srv_sort')):
/*
 * $records is as returned by dns_get_record.
 * This call will extract and sort DNS SRV records  as RFC2782 specifiies.
 * Any non-SRV record will be discarded in the response.
 * @return an array where each item is itself an array with a 'port' and a 'server'
 * and where the index order matters for connection attempts.
 */
function dns_srv_sort($records)
{
	$targets = array();
	$recs = array ();
    // 1 week in second. Too long ttls should be avoided.
    // See RFC-1035, section 7.3 (Processing Responses).
    $ttl = 604800;
	foreach ($records as $rr)
	{
        // TODO: maybe I should check the expected host as well.
		if ($rr['type'] <> 'SRV')
			continue;
		$rec = array ();
		$rec['target'] = $rr['target'];
		$rec['port'] = $rr['port'];
		$rec['weight'] = $rr['weight'];
		//$rec['ttl'] = $rr['ttl'];
		$recs[$rr['pri']][] = $rec;
        // I want to use a single ttl for all records, which is the minimum ttl.
        // I indeed consider that if one record terminate, I should probably check the whole query again.
        $ttl = min($ttl, $rr['ttl']);
	}
    $ttl += time(); // Convert the ttl from relative to absolute for caching.

	ksort($recs);
	foreach ($recs as $rrs)
	{
		if (count($rrs) == 1)
			$targets[] = array(
                'port' => $rrs[0]['port'],
                'server' => $rrs[0]['target'],
                'ttl' => $ttl);
		else
		{
			function nul_first($a, $b)
			{
				if ($a['weight'] == 0 && $b['weight'] == 0)
					return 0;
				if ($a['weight'] == 0)
					return -1; // nul weighted records are first.
				if ($b['weight'] == 0)
					return 1; // nul weighted records are first.
				else
					return 0; // other than this, I don't care.
			}

			usort($rrs, 'nul_first');
			$w_sum = 0;
			while (TRUE)
			{
				foreach ($rrs as &$rr)
				{
					$w_sum += $rr['weight'];
					$rr['w_sum'] = $w_sum;
				}
                unset($rr);
				$rand_num = rand(0, $w_sum);
				foreach ($rrs as $k => $rr)
				{
					if ($rr['w_sum'] >= $rand_num)
					{
						$targets[] = array(
								'port' => $rr['port'],
								'server' => $rr['target'],
                                'ttl' => $ttl);
                        unset($rrs[$k]);
						break;
					}
				}
                if (count($rrs) == 0)
                    break;
			}
		}
	}
	return $targets;
}
endif;

?>

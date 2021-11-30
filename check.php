<?php
error_reporting(0);

$ip = $_POST['ip'];

$rbllisted=0;
$rbl_count=0;
$openports=0;
$rblnr=0;

$portcheck=array("21","22","23","25","53","80","110","113","137","138","139","143","443","445","465","548","587","993","995","1433","1701","1723","3306","3389","5432","8080");
$totalports=count($portcheck);

if (ob_get_level() == 0) ob_start();

echo "<div id=\"info\" style=\"width:33%; height:100%; float:left;\">";
echo "IP Blacklist Checker 1.0 Developed by Sahil Dhamija - <a href='https://github.com/sahildhamija/ip-blacklist-checker-php' target='_blank'>Code</a><br><br>";
echo "Your IP: $ip<br>";

echo get_asn($ip);
echo "<br><br>This check could take some time!<br>";
echo str_pad('',4096)."\n";
ob_flush();
flush();
sleep(1);
echo "</div>";

function get_asn($ip) {
    $details = json_decode(file_get_contents("http://ipinfo.io/{$ip}"));
    return $details->org;
}


function dnsbllookup($ip){ global $rbl_count; global $rbllisted;
    $dnsbl_lookup=array('b.barracudacentral.org',
        'cbl.abuseat.org',
        'http.dnsbl.sorbs.net',
        'misc.dnsbl.sorbs.net',
        'socks.dnsbl.sorbs.net',
        'web.dnsbl.sorbs.net',
        'dnsbl-1.uceprotect.net',
        'dnsbl-3.uceprotect.net',
        'sbl.spamhaus.org',
        'zen.spamhaus.org',
        'psbl.surriel.com',
        'dnsbl.njabl.org',
        'rbl.spamlab.com',
        'noptr.spamrats.com',
        'cbl.anti-spam.org.cn',
        'dnsbl.inps.de',
        'httpbl.abuse.ch',
        'korea.services.net',
        'virus.rbl.jp',
        'wormrbl.imp.ch',
        'rbl.suresupport.com',
        'ips.backscatterer.org',
        'opm.tornevall.org',
        'multi.surbl.org',
        'tor.dan.me.uk',
        'relays.mail-abuse.org',
        'rbl-plus.mail-abuse.org',
        'access.redhawk.org',
        'rbl.interserver.net',
        'bogons.cymru.com',
        'bl.spamcop.net',
        'dnsbl.sorbs.net',
        'dul.dnsbl.sorbs.net',
        'smtp.dnsbl.sorbs.net',
        'spam.dnsbl.sorbs.net',
        'zombie.dnsbl.sorbs.net',
        'dnsbl-2.uceprotect.net',
        'pbl.spamhaus.org',
        'xbl.spamhaus.org',
        'bl.spamcannibal.org',
        'ubl.unsubscore.com',
        'combined.njabl.org',
        'dyna.spamrats.com',
        'spam.spamrats.com',
        'cdl.anti-spam.org.cn',
        'drone.abuse.ch',
        'dul.ru',
        'short.rbl.jp',
        'spamrbl.imp.ch',
        'virbl.bit.nl',
        'dsn.rfc-ignorant.org',
        'dsn.rfc-ignorant.org',
        'netblock.pedantic.org',
        'ix.dnsbl.manitu.net',
        'rbl.efnetrbl.org',
        'blackholes.mail-abuse.org',
        'dnsbl.dronebl.org',
        'db.wpbl.info',
        'query.senderbase.org',
        'bl.emailbasura.org',
        'combined.rbl.msrbl.net',
        'cblless.anti-spam.org.cn',
        'cblplus.anti-spam.org.cn',
        'blackholes.five-ten-sg.com',
        'sorbs.dnsbl.net.au',
        'rmst.dnsbl.net.au',
        'dnsbl.kempt.net',
        'blacklist.woody.ch',
        'rot.blackhole.cantv.net',
        'virus.rbl.msrbl.net',
        'phishing.rbl.msrbl.net',
        'images.rbl.msrbl.net',
        'spam.rbl.msrbl.net',
        'spamlist.or.kr',
        'dnsbl.abuse.ch',
        'bl.deadbeef.com',
        'ricn.dnsbl.net.au',
        'forbidden.icm.edu.pl',
        'probes.dnsbl.net.au',
        'ubl.lashback.com',
        'ksi.dnsbl.net.au',
        'uribl.swinog.ch',
        'bsb.spamlookup.net',
        'dob.sibl.support-intelligence.net',
        'url.rbl.jp',
        'dyndns.rbl.jp',
        'omrs.dnsbl.net.au',
        'osrs.dnsbl.net.au',
        'orvedb.aupads.org',
        'relays.nether.net',
        'relays.bl.gweep.ca',
        'relays.bl.kundenserver.de',
        'dialups.mail-abuse.org',
        'rdts.dnsbl.net.au',
        'duinv.aupads.org',
        'dynablock.sorbs.net',
        'residential.block.transip.nl',
        'dynip.rothen.com',
        'dul.blackhole.cantv.net',
        'mail.people.it',
        'blacklist.sci.kun.nl',
        'all.spamblock.unit.liu.se',
        'spamguard.leadmon.net',
    'csi.cloudmark.com'
);
echo "<div id=\"rbl\" style=\"width:33%; height:100%; float:right; top:0px;\">";
$rbl_count = count($dnsbl_lookup);
echo "RBL Check ($rbl_count to check)<br><br>";

if($ip){
 $reverse_ip=implode(".",array_reverse(explode(".",$ip)));
 foreach($dnsbl_lookup as $host){
  if(checkdnsrr($reverse_ip.".".$host.".","A")){
        $listed="$host - <font color=\"red\">LISTED</font><br />";
        $rbllisted++;
        }else{
    $listed="$host - <font color=\"green\">OK</font><br />";
}
        $rblnr++;
        echo "$rblnr Checking: $listed";
        echo str_pad('',4096)."\n";
        ob_flush();
        flush();
  }
 }
echo "</div>";
}

echo "<div id=\"ports\" style=\"width:33%; height:100%; float:left; margin:0 auto; top:0px;\">";

echo "Testing for open ports at you.<br><br>";
echo str_pad('',4096)."\n";
ob_flush();
flush();


function ping($host, $port) { global $openports;
  $fP = fSockOpen($host, $port, $errno, $errstr, 1);
  if (!$fP) { return "<tr><td>Port: $port (". getservbyport($port, "tcp") .") - <font color=red> Closed or not responding.</font><br></tr></td>"; }
  $openports++;
  return "<tr><td>Port: $port (". getservbyport($port, "tcp") .") - <font color=green> OPEN</font><br></tr></td>";
}
foreach($portcheck as $myport){
echo ping("$ip", "$myport");
echo str_pad('',4096)."\n";
ob_flush();
flush();
}
echo "</div>";

dnsbllookup($ip);

$testdone="<br>Test Done..<br><br>Result from tests:<br>Ports open $openports of $totalports tested<br>IP is listet $rbllisted of $rbl_count";
echo "<script>";
echo "document.getElementById('info').innerHTML+='<h2>$testdone</h2>';";
echo "</script>";

echo "<noscript>";
echo "<style type=\"text/css\">";
echo ".pagecontainer {display:none;}";
echo "</style>";
echo "<div class=\"noscriptmsg\">";
echo "$testdone";
echo "</div>";
echo "</noscript>";

echo "</body></html>";
ob_end_flush();

?>
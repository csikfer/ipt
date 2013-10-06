####################################################################
#
#    This file was generated using Parse::Yapp version 1.05.
#
#        Don't edit this file, use source file instead.
#
#             ANY CHANGE MADE HERE WILL BE LOST !
#
####################################################################
package iptcon;
use vars qw ( @ISA );
use strict;

@ISA= qw ( Parse::Yapp::Driver );
use Parse::Yapp::Driver;

#line 4 "iptcon.py"

    # Munka vátozók
    our ($MySelf,      # A hibakezeléshez használom
         @chst,        # Stack a CH definíciókhoz
	 %services,
	 $deblev,	# Debug level
	 $cnt);
    # Az 'eredmény'
    our ($nat,         # nat szekció lefordított definíciói (iptables-ba kiírandó szöveg)
         $filt,        # filter szekci szabályok lefordított definíciói (iptables-ba kiírandó szöveg)
	 %pol,	       # Policy
         %chs,         # Hívott/definiált CH-k 
	 @mods);       # Betöltendő modulok.
    $nat = $filt = '';
    %pol = ( INPUT => 'DROP', OUTPUT => 'DROP', FORWARD => 'DROP' );
    # SYMBOLS:
    our (%macros,      # Makrók
         %ifs,         # Interfészek
         %ifaces,      # Interfészek (IFACES opció)
         %lans,        # IP tartományok
         %ips,         # IP címek
         %ports,       # Portok (port/protocol)
         %protos,      # Protokolok
         %icmpts);     # Icmp tipusok
    our %null = ();
#-----------------------------------------------------------------------------------------
    sub __error {
        $MySelf->YYData->{ERRMSG} = "$_[0]\n" if (defined($_[0]));
        #$MySelf->yyerror();
	&_Error($MySelf);
        exit(1);
    }
#-----------------------------------------------------------------------------------------
    sub dpr {
	print STDERR "$_[1]" if (defined($deblev) && int($_[0]) <= $deblev); 
    }
#-----------------------------------------------------------------------------------------
    sub addmod {
       my $modn, ;
       AML1: foreach $modn (@_) {
          foreach (@mods) {
             next AML1 if ($_ eq $modn);
          }
	  push(@mods, $modn);
       }
    }
#-----------------------------------------------------------------------------------------
    sub ipmsk {
        my ($ipm, $if) = @_;
        $ifaces{$if} = $ipm;
	#print STDERR "ipmask($ipm, $if)\n";
	my ($ip, $msk, $res);
        if ($ipm =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
            $ip  = $1;
	    $ip  = $ip  * 256 + $2;
	    $ip  = $ip  * 256 + $3;
	    $ip  = $ip  * 256 + $4;
            $msk = $5;
	    $msk = $msk * 256 + $6;
	    $msk = $msk * 256 + $7;
	    $msk = $msk * 256 + $8;
        }
	elsif ($ipm =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/) {
            $ip  = $1;
	    $ip  = $ip  * 256 + $2;
	    $ip  = $ip  * 256 + $3;
	    $ip  = $ip  * 256 + $4;
            $msk = $5;
            if ($msk) { $msk = ~((1 << (32 - $msk)) -1); }
        }
	else {
           __error("Invalid net: '$ipm'. (Program error.)");
        }
	$ip &= $msk;
	$res  = ($ip % 256) . '.';
	$ip  /= 256;
	$res .= ($ip % 256) . '.';
	$ip  /= 256;
	$res .= ($ip % 256) . '.';
	$ip  /= 256;
	$res .= $ip;
	return $ip
    }
#-----------------------------------------------------------------------------------------
    sub hashcat {
        my ($pa,$pb) = @_;
        return $pa unless(defined($pb));
        my %r = (%$pa, %$pb);
        return \%r;
    }
#-----------------------------------------------------------------------------------------
    sub ldservices() {
        my ($services) = '/etc/services';
        unless (open(SERVICES, "<$services")) {
	    print STDERR "Warning: $services file open error: $!.\n";
	    return;
	}
        while (<SERVICES>) {
	    dpr(9,"SERVICES: $_");
            chomp;
            s/#.*$//;               #komment torlese
            next if m/^\s*$/;       #ures sorok kihajtasa
            next unless m/^([\w\-]+)\s+(\d+)\/\w+/;
	    dpr(9,"LdServices: $1 : $2\n");
            $services{$1} = $2;     # servicename => port number
        }
    }
#-----------------------------------------------------------------------------------------
    sub chkservice {
	my $x = %services;
        ldservices() unless($x);
        __error("Invalid service name: '$_[0]'.") unless (defined($services{$_[0]}));
        return $services{$_[0]};
    }
#-----------------------------------------------------------------------------------------
    sub chkparams {
        my ($pp, @lst) = @_;
        # Az üres paramétereket töröljük
        for (keys(%$pp)) { delete $pp->{$_} if ($pp->{$_} =~ m/^;*$/); }
        my %p = %$pp;
        # A másolaton töröljük azokat a paramétereket, amik megengedettek:
        foreach (@lst) { delete ($p{$_}) if (defined($p{$_})); }
        # Ha maradt paraméter, akkor az nem megengedet paraméter, hiba!
        if (%p) {
            my $p = join(',', keys(%p));
            __error("Invalid params: $p");
        }
    }
#-----------------------------------------------------------------------------------------
    sub ch {
        my $nm = $_[0];
        __error("Redefined CH $nm") if (defined($chs{$nm}) && $chs{$nm} =~ "D");
        push(@chst, $nm);
        $chs{$nm} = defined($chs{$nm}) ? $chs{$nm} . "D" : "D";
    }
#-----------------------------------------------------------------------------------------
    sub xcat {
        my $ref = shift;
        my @res;
        for (@_) {
            my $cat = $_;
            for (@$ref) {
                push(@res, "$_ $cat");
            }
        }
        return @res;
    }
#-----------------------------------------------------------------------------------------
    sub protocat {
        my ($ref, $prolst, @port) = @_;
        my @cmd = @$ref;
	$prolst = 'tcp' if (!$prolst && (defined($port[0]) && $port[0]
	                              || defined($port[1]) && $port[1]));
        if ($prolst) {
            my @proto = split(/,/,$prolst);
            for (@proto) {
                __error("Parameter conflict: Port is defined and PROTO=$_ (is not udp or tcp)")
		  if (!m/^udp/i && !m/^tcp/i
				&& defined($port[0]) && $port[0]
		    		&& defined($port[1]) && $port[1]);
                $_ = "-p $_ ";
            }
            return xcat(\@cmd, @proto);
        }
        return @cmd;
    }
#-----------------------------------------------------------------------------------------
    sub portcat {
        my $type = shift;
        my ($ref, $plst) = @_;
	my $pstr;
	my @res = ();
        if ($plst) {
            my @port;
            my @p = split(/,/,$plst);
            my @plst = (); #Lista
            my @pbou = (); #Tartom�y
            for (@p) {
                if (m/:/) { push(@pbou, $_); }
                else      { push(@plst, $_); }
            }
	    if (@plst == 1) {	# Ha csak egy van, akkor nem kell a -m multiport
	        push(@pbou,$plst[0]);
		@plst = ();
	    }
            for (@pbou) {
                $pstr = ($type eq 'D' ? "--dport" : "--sport") . " $_ ";
                for my $cmd (@$ref) {
	            push(@res, "$cmd $pstr");
    	        }
            };
            while (@plst) {
		my $len = @plst;
		my $sll = $len > 16 ? 15 : $len -1;
                $plst = join(',', @plst[0..$sll]);
		my $mp = '';
		$mp = "-m multiport " if ($sll > 0);
                $pstr = ($type eq 'D' ? "--dports" : "--sports") . " $plst ";
                @plst = defined($plst[16]) ? @plst[16..$len] : ();
		
                for my $Cmd (@$ref) {
		    $mp = '' if ($mp && $Cmd =~ m/$mp/);
	            push(@res, "$Cmd $mp$pstr");
    	        }
            }
        }
	else {
	   @res = @$ref;
	}
        return @res;
    }
##################################################################################################
    sub redirect {
# -A PREROUTING [-i <IF>] [-s [!]<SIP>] [-d [!]<frm|DIP>] [-p <PROTO>]
#    [{ -m multiport [--sports [!]<SPORT>] [-dports [!]<DPORT>]
#     | [--sport [!]<SPORT>] [--dport [!]<DPORT>] }]
#    -j DNAT  <to>:<top>
        my ($frm, $to, $top, $par) = @_;
        chkparams($par, 'IF', 'IPTO', 'PORTTO', 'PROTO');   # Megengedett param�erek
        my $IF              = defined($par->{IF})     ? $par->{IF}                :  '';
        my ($SIP,$DIP)      = defined($par->{IPTO})   ? split(/;/,$par->{IPTO})   : ('','');
        my ($SPORT, $DPORT) = defined($par->{PORTTO}) ? split(/;/,$par->{PORTTO}) : ('','');
        my $PROTO           = defined($par->{PROTO})  ? $par->{PROTO}             :  '';
        # Ha az átirányítás célja több port
        if ($top =~ m/,/ || $top =~ m/:/) {
            __error("Port numbers parameter(s) conflict") if ($DPORT && $DPORT ne $top);
            #Nem foglalkozunk a c� porttal az �ir�yit�n�, csak a felt�eln�
            $DPORT = $top;
            $top = '';
        }
        __error("Source port parameter(s) not supported") if ($SPORT);
        __error("Dest. IP parameter(s) conflict") if ($frm && $DIP && $frm ne $DIP);
        __error("Phisycal interface is not supported here: $IF") if ($IF =~ m/\//);
        $DIP = $frm if ($frm);
        # DPORT � PROTO kiv�el�el minden param�er O.K., t�sz�� hiv. t��ve
        my $cmd = "-A PREROUTING ";
        $cmd .= "-i $IF "  if ($IF);
        $cmd .= "-s $SIP " if ($SIP);
        $cmd .= "-d $DIP " if ($DIP);
        my @cmd = ($cmd);   #Innent� osztodhat
        @cmd = protocat(\@cmd, $PROTO, $DPORT);
        @cmd = portcat('D', \@cmd, $DPORT);
        $cmd  = "-j DNAT --to-destination $to";
        $cmd .= ":$top"    if ($top);
        $cmd .= "\n";
        @cmd = xcat(\@cmd, $cmd);
        # K�z, hozz�djuk a kimeneti stringhez:
        for $cmd (@cmd) {
            dpr(3,"red : $cmd");
            $nat .= $cmd;
        }
    }
##################################################################################################
    sub masqu {
# -A POSTROUTING -i [!]<SIF> -o [!]<DIF> [-s [!]<SIP>] [-d [!]<frm|DIP>] [-p <PROTO>]
#    [{ -m multiport [--sports [!]<SPORT>] [-dports [!]<DPORT>]
#     | [--sport [!]<SPORT>] [--dport [!]<DPORT>] }]
#   -j MASQUERADE
        my ($lan, $oif, $par) = @_;
        chkparams($par, 'IFTO', 'IPTO', 'PORTTO', 'PROTO');   # Megengedett param�erek
        my ($SIF,$DIF)     = defined($par->{IFTO})   ? split(/;/,$par->{IFTO})   : ('','');
        my ($SIP,$DIP)     = defined($par->{IPTO})   ? split(/;/,$par->{IPTO})   : ('','');
        my ($SPORT,$DPORT) = defined($par->{PORTTO}) ? split(/;/,$par->{PORTTO}) : ('','');
        my $PROTO          = defined($par->{PROTO})  ? $par->{PROTO}             :  '';
        # Kett� felt�elek:
        __error("NET parameter(s) conflict") if ($lan && $SIP && $lan ne $SIP);
        __error("IF  parameter(s) conflict") if ($oif && $DIF && $oif ne $DIF);
        $SIP = $lan if ($lan);
        $DIF = $oif if ($oif);
        __error("Phisycal interface is not supported here: $SIF,$DIF") if ($SIF =~ m/\// || $DIF =~ m/\//);
        # SPORT, DPORT � PROTO kiv�el�el minden param�er O.K., t�sz�� hiv. t��ve
        my $cmd = "-A POSTROUTING ";
        $cmd .= "-i $SIF " if ($SIF);
        $cmd .= "-o $DIF " if ($DIF);
        $cmd .= "-s $SIP " if ($SIP);
        $cmd .= "-d $DIP " if ($DIP);
        my @cmd = ($cmd);   #Innent� osztodhat
        @cmd = protocat(\@cmd, $PROTO, $SPORT, $DPORT);
        @cmd = portcat('S', \@cmd, $SPORT);
        @cmd = portcat('D', \@cmd, $DPORT);
        @cmd = xcat(\@cmd, "-j MASQUERADE\n");
        # K�z, hozz�djuk a kimeneti stringhez:
        for $cmd (@cmd) {
            dpr(3,"msq : $cmd");     #debug
            $nat .= $cmd;
        }
    }
##################################################################################################
    sub act {
        my ($iofw, $act, $par) = @_;
        # Firts : My,  Source ...
        # Second: Our, Target ...
        my ($myIF,$yourIF,$myIP,$yourIP,$myPORT,$yourPORT,$PROTO,$ICMPT,$USER,$GROUP,$myPIF,$yourPIF) =
	   ('','','','','','','','','','','','');
        dpr(8,"$iofw,$act: if ... chk ...\n");
        my $symple = 1;
        if ($iofw eq 'IO') {
            if    ($act eq 'SERVICE') {
                # INPUT
                chkparams($par, 'IF', 'CLIENT', 'PORT', 'PROTO', 'USER');   # Megengedett paraméterek
                $myIF    = $par->{IF}      if (defined($par->{IF}));
                $yourIP  = $par->{CLIENT}  if (defined($par->{CLIENT}));
                $myPORT  = $par->{PORT}    if (defined($par->{PORT}));
                $PROTO   = $par->{PROTO}   if (defined($par->{PROTO}));
                $USER    = $par->{USER}    if (defined($par->{USER}));
                $GROUP   = $par->{GROUP}   if (defined($par->{GROUP}));
            }
            elsif ($act eq 'USE') {
                chkparams($par, 'IF', 'SERVER', 'PORT', 'PROTO', 'USER');   # Megengedett paraméterek
                $myIF    = $par->{IF}      if (defined($par->{IF}));
                $yourIP  = $par->{SERVER}  if (defined($par->{SERVER}));
                $yourPORT= $par->{PORT}    if (defined($par->{PORT}));
                $PROTO   = $par->{PROTO}   if (defined($par->{PROTO}));
                $USER    = $par->{USER}    if (defined($par->{USER}));
                $GROUP   = $par->{GROUP}   if (defined($par->{GROUP}));
            }
            else {
                chkparams($par, 'IF', 'MYIP', 'YOURIP', 'MYPORT','YOURPORT', 'PROTO', 'USER'); # ,'ICMPT');   # Megengedett paraméterek
                $myIF    = $par->{IF}      if (defined($par->{IF}));
                $myIP    = $par->{MYIP}    if (defined($par->{MYIP}));
                $yourIP  = $par->{YOURIP}  if (defined($par->{YOURIP}));
                $myPORT  = $par->{MYPORT}  if (defined($par->{MYPORT}));
                $yourPORT= $par->{YOURPORT}if (defined($par->{YOURPORT}));
                $PROTO   = $par->{PROTO}   if (defined($par->{PROTO}));
                $ICMPT   = $par->{ICMPT}   if (defined($par->{ICMPT}));
                $USER    = $par->{USER}    if (defined($par->{USER}));
                $GROUP   = $par->{GROUP}   if (defined($par->{GROUP}));
            }
        }
        elsif ($iofw eq 'FW') {
	    # a felénk néző interfészen a felénk input, az az interfésznek output, tehát pont fordítva működik !!!!
	    # ezért a myIF és yourIF fel van cserélve !!!
            if    ($act eq 'SERVICE') {
                chkparams($par, 'IFTO', 'SERVER', 'CLIENT', 'PORT', 'PROTO');   # Megengedett param�erek
                ($yourIF,$myIF) = split(/;/,$par->{IFTO})    if (defined($par->{IFTO}));
                $myIP     = $par->{SERVER} if (defined($par->{SERVER}));
                $yourIP   = $par->{CLIENT} if (defined($par->{CLIENT}));
                $myPORT   = $par->{PORT}   if (defined($par->{PORT}));
                $PROTO    = $par->{PROTO}  if (defined($par->{PROTO}));
            }
            elsif ($act eq 'USE') {
                chkparams($par, 'IFTO', 'SERVER', 'CLIENT', 'PORT', 'PROTO');   # Megengedett param�erek
                ($yourIF,$myIF) = split(/;/,$par->{IFTO})    if (defined($par->{IFTO}));
                $myIP     = $par->{CLIENT} if (defined($par->{CLIENT}));
                $yourIP   = $par->{SERVER} if (defined($par->{SERVER}));
                $yourPORT = $par->{PORT}   if (defined($par->{PORT}));
                $PROTO    = $par->{PROTO}  if (defined($par->{PROTO}));
            }
            else {
                chkparams($par, 'IF', 'IFTO', 'IP', 'IPTO', 'PORT', 'PORTTO', 'PROTO'); # ,'ICMPT');   # Megengedett param�erek
                if (defined($par->{IF}) && defined($par->{IFTO})    # Kettős paraméerezés
                 || defined($par->{IP}) && defined($par->{IPTO})
                 || defined($par->{PORT}) && defined($par->{PORTTO})) {
                    __error("Parameter conflict. (redundant IP or IF or PORT params.)");
                }
                ($yourIF,$myIF)     = split(/;/,$par->{IFTO})   if (defined($par->{IFTO}));
                ($myIP,$yourIP)     = split(/;/,$par->{IPTO})   if (defined($par->{IPTO}));
                ($myPORT,$yourPORT) = split(/;/,$par->{PORTTO}) if (defined($par->{PORTTO}));
                $yourIF  = $par->{IF}    if (defined($par->{IF}));
                $myIP    = $par->{IP}    if (defined($par->{IP}));
                $myPORT  = $par->{PORT}  if (defined($par->{PORT}));
                $PROTO   = $par->{PROTO} if (defined($par->{PROTO}));
                $ICMPT   = $par->{ICMPT} if (defined($par->{ICMPT}));
            }
        }
        else {  __error("Program error: \$iofw = '$iofw'."); } #Ilyen állat nincsen
        $PROTO = 'tcp'  if (($myPORT || $yourPORT) && !$PROTO);
        $PROTO = 'icmp' if ($ICMPT && !$PROTO);
        __error("Invalid protocol $PROTO for ICMPTYPE params.") if ($ICMPT && $PROTO ne 'icmp');
	__error("Parameter (USER and GROUP) conflict") if ($USER && $GROUP);
	($myIF,   $myPIF)   = split(/\//, $myIF)   if ($myIF   && $myIF   =~ m/\//);
	($yourIF, $yourPIF) = split(/\//, $yourIF) if ($yourIF && $yourIF =~ m/\//);
        my (@cmdi, @cmdo, $cmdi, $cmdo, $chin, $chout);
        # A lánc neve, ahova a szabályt el kell helyezni:
        if    (@chst)         { my $ch = $chst[@chst -1]; $chin = $ch . 'i'; $chout = $ch . 'o'; }
        elsif ($iofw eq 'IO') { $chin = 'INPUT'; $chout = 'OUTPUT'; }
        elsif ($iofw eq 'FW') { $chin = $chout = 'FORWARD'; }
        else                  { __error("Program error: \$iofw = '$iofw' (2)."); }
        $cmdi  = "-A $chin ";
        $cmdo  = "-A $chout ";
        $cmdi .= "-i $myIF "   if ($myIF);
        $cmdi .= "-m physdev --physdev-in $myPIF " 	if ($myPIF);
        $cmdi .= "-o $yourIF " if ($yourIF); 
        $cmdi .= "-m physdev --physdev-out $yourPIF " 	if ($yourPIF);
        $cmdo .= "-o $myIF "   if ($myIF);
        $cmdo .= "-m physdev --physdev-out $myPIF " 	if ($myPIF);
        $cmdo .= "-i $yourIF " if ($yourIF);
        $cmdo .= "-m physdev --physdev-in $yourPIF " 	if ($yourPIF);
        $cmdi .= "-d $myIP "   if ($myIP);
        $cmdi .= "-s $yourIP " if ($yourIP); 
        $cmdo .= "-s $myIP "   if ($myIP);
        $cmdo .= "-d $yourIP " if ($yourIP);
	$cmdo .= "-m owner --uid-owner $USER "  if ($USER);	#csak a kimeno csomagokra
	$cmdo .= "-m owner --gid-owner $GROUP " if ($GROUP);	#csak a kimeno csomagokra
        @cmdi = ($cmdi);
        @cmdo = ($cmdo);
        @cmdi = protocat(\@cmdi, $PROTO, $myPORT, $yourPORT);
        @cmdo = protocat(\@cmdo, $PROTO, $myPORT, $yourPORT);
        @cmdi = portcat('D', \@cmdi, $myPORT);
        @cmdo = portcat('S', \@cmdo, $myPORT);
        @cmdi = portcat('S', \@cmdi, $yourPORT);
        @cmdo = portcat('D', \@cmdo, $yourPORT);
        my $action = $act;
        if ($action =~ m/USE|SERVICE/) {
            my ($is, $os);
            # A kiépített kapcsolatok mehetnek
            $is = $os = "-m state --state ESTABLISHED";
            # Ha nincs megadva szolgáltatás, akkor a RELATED is O.K.
            $is = $os .= ",RELATED" unless ($myPORT || $yourPORT);
            # Melyik irányba kezdeményezheto a kapcsolat:
            if ($act =~ m/SERVICE/) { $is .= ",NEW "; $os .= ' '; }
            else                    { $os .= ",NEW "; $is .= ' '; }
            @cmdi = xcat(\@cmdi, $is);
            @cmdo = xcat(\@cmdo, $os);
            $action = 'ACCEPT';
        }
        if ($action =~ m/ACCEPT|DROP|REJECT|RETURN|LOG|logdrop/) {
            @cmdi = xcat(\@cmdi, "-j $action\n");
            @cmdo = xcat(\@cmdo, "-j $action\n");
        }
        else {
            if (defined($chs{$act})) {
                $chs{$action} .= 'R' unless ($chs{$action} =~ m/R/);
            }
            else {
                $chs{$action} = 'R';
            }
            @cmdi = xcat(\@cmdi, "-j ${action}i\n");
            @cmdo = xcat(\@cmdo, "-j ${action}o\n");
            $symple = 0;
        }
        for $cmdi (@cmdi) {
            dpr(3,"act(i) : $cmdi");     #debug
            $filt .= $cmdi;
        }
#        unless ($iofw eq 'FW' && $symple    # Ha FORWARD, egyszerű cél és szimmetrikusak a paraméerek
#         && $myIP eq $yourIP && $myIF eq $yourIF && $myPIF eq $yourPIF && $myPORT eq $yourPORT) {
        #, Akkor nem kell a vissz irany, mert ugyan az lenne, mint az elozo.
            for $cmdo (@cmdo) {
                dpr(3,"act(o) : $cmdo");     #debug
                $filt .= $cmdo;
            }
#        }
        dpr(6, "act end: PROTO=$PROTO, myPORT=$myPORT, yourPORT=$yourPORT, act=$act\n");
        # Extra okossagok a protokolokhoz (USE vagy SERVICE eseten)
        if ($PROTO eq 'tcp' && ($myPORT || $yourPORT) && ($act eq 'SERVICE' || $act eq 'USE')) {
            dpr(7, "scan port (tcp) ...\n");
            my %port;
            for (split(/,/,$myPORT ? $myPORT : $yourPORT)) { $port{$_} = $_; }
            if (defined($port{21}) && $PROTO eq 'tcp') {   # ftp/tcp            !!!!!!!!!!!!!!!!!??????
                dpr(1,"ftp protocol detect ...\n");
                $cmdi = "-A $chin ";
                $cmdo = "-A $chout ";
                $cmdi .= "-i $myIF "   if ($myIF);
                $cmdi .= "-o $yourIF " if ($yourIF); 
                $cmdo .= "-o $myIF "   if ($myIF);
                $cmdo .= "-i $yourIF " if ($yourIF);
                $cmdi .= "-d $myIP "   if ($myIP);
                $cmdi .= "-s $yourIP " if ($yourIP); 
                $cmdo .= "-s $myIP "   if ($myIP);
                $cmdo .= "-d $yourIP " if ($yourIP);
                $cmdi .= "-p tcp ";
                $cmdo .= "-p tcp ";
                $filt .= $cmdi . "--dport 20    -m state --state ESTABLISHED,RELATED -j ACCEPT\n";
                $filt .= $cmdo . "--sport 20    -m state --state ESTABLISHED,RELATED -j ACCEPT\n";
                $filt .= $cmdi . "--dport 1024: -m state --state ESTABLISHED,RELATED -j ACCEPT\n";
                $filt .= $cmdo . "--sport 1024: -m state --state ESTABLISHED,RELATED -j ACCEPT\n";
                addmod('ip_conntrack_ftp');
            }
        }
        if ($PROTO eq 'udp' && ($myPORT || $yourPORT) && ($act eq 'SERVICE' || $act eq 'USE')) {
            dpr(7, "scan port (udp)...\n");
            my %Port;
            for (split(/,/,$myPORT ? $myPORT : $yourPORT)) { $Port{$_} = $_; }
            if (defined($Port{69}) && $PROTO eq 'udp') {   # tftp/ucp            !!!!!!!!!!!!!!!!!??????
                addmod('ip_conntrack_tftp');
            }
        }
    }
##################################################################################################
    sub raw {
	my ($str) = @_;
	my ($nm, $ty);
	CHG: while ($str =~ m/\$/) {
	    if ($str =~ s/\$\{([^\}]+)\}/\$/) {
	        $nm = $1;	# Teljes makro nev
		goto scanall unless ($nm =~ m/:/);
		($ty,$nm) = split(/:/,$nm);
		goto scan;    
	    }
	    elsif ($str =~ s/\$(\w+):(\w+)/\$/) {
		$ty = $1;
		$nm = $2;
		goto scan;
	    }
	    elsif ($str =~ s/\$(\w+)/\$/) {
		$nm = $1;
		goto scanall;
	    }
	    else {
		__error("Invalid var. in \"$_[0]\" string.");
	    }
	scanall:
	    if    (defined($ifs{$nm}))   { $str =~ s/\$/$ifs{$nm}/;   }
	    elsif (defined($lans{$nm}))  { $str =~ s/\$/$lans{$nm}/;  }
	    elsif (defined($ips{$nm}))   { $str =~ s/\$/$ips{$nm}/;   }
	    elsif (defined($ports{$nm})) { $str =~ s/\$/$ports{$nm}/; }
	    elsif (defined($protos{$nm})){ $str =~ s/\$/$protos{$nm}/;}
	    elsif (defined($icmpts{$nm})){ $str =~ s/\$/$icmpts{$nm}/;}
	    else  {
		__error("\"$nm\"var. (any type)  not found in \"$_[0]\" string.")
	    }
	    next CHG;
	scan:
	    if    ($ty =~ m/^IF$/) {
	        __error("\"$nm\"var. not found in \"$_[0]\" string.") unless (defined($ifs{$nm}));
		$str =~ s/\$/$ifs{$nm}/;
	    }
	    elsif ($ty =~ m/^LAN$/) {
	        __error("\"$nm\"var. not found in \"$_[0]\" string.") unless (defined($lans{$nm}));
		$str =~ s/\$/$lans{$nm}/;
	    }
	    elsif ($ty =~ m/^IP$/) {
	        __error("\"$nm\"var. not found in \"$_[0]\" string.") unless (defined($ips{$nm}));
		$str =~ s/\$/$ips{$nm}/;
	    }
	    elsif ($ty =~ m/^PORT$/) {
	        __error("\"$nm\"var. not found in \"$_[0]\" string.") unless (defined($ports{$nm}));
		$str =~ s/\$/$ports{$nm}/;
	    }
	    elsif ($ty =~ m/^PROTO$/) {
	        __error("\"$nm\"var. not found in \"$_[0]\" string.") unless (defined($protos{$nm}));
		$str =~ s/\$/$protos{$nm}/;
	    }
	    elsif ($ty =~ m/^ICMPT$/) {
	        __error("\"$nm\"var. not found in \"$_[0]\" string.") unless (defined($icmpts{$nm}));
		$str =~ s/\$/$icmpts{$nm}/;
	    }
	    else  {
		__error("Invalid var. type \"$ty\" in \"$_[0]\" string.");
	    }
	    next CHG;
	}
	return $str . "\n";
    }    


sub new {
        my($class)=shift;
        ref($class)
    and $class=ref($class);

    my($self)=$class->SUPER::new( yyversion => '1.05',
                                  yystates =>
[
	{#State 0
		ACTIONS => {
			'ICMPTYPE' => 1,
			'HOST' => 3,
			'PROTO' => 6,
			'MACRO' => 7,
			'IF' => 8,
			'IP' => 9,
			'LAN' => 10,
			'PORT' => 12,
			'IFLAN' => 11
		},
		DEFAULT => -3,
		GOTOS => {
			'defines' => 2,
			'all' => 5,
			'define' => 4
		}
	},
	{#State 1
		ACTIONS => {
			'NAME' => 13
		}
	},
	{#State 2
		ACTIONS => {
			'NAT' => 14
		}
	},
	{#State 3
		ACTIONS => {
			'NAME' => 15
		}
	},
	{#State 4
		ACTIONS => {
			'ICMPTYPE' => 1,
			'HOST' => 3,
			'PROTO' => 6,
			'IF' => 8,
			'MACRO' => 7,
			'IP' => 9,
			'LAN' => 10,
			'IFLAN' => 11,
			'PORT' => 12
		},
		DEFAULT => -3,
		GOTOS => {
			'defines' => 16,
			'define' => 4
		}
	},
	{#State 5
		ACTIONS => {
			'' => 17
		}
	},
	{#State 6
		ACTIONS => {
			'NAME' => 18
		}
	},
	{#State 7
		ACTIONS => {
			'NAME' => 19
		}
	},
	{#State 8
		ACTIONS => {
			'NAME' => 20
		}
	},
	{#State 9
		ACTIONS => {
			'NAME' => 21
		}
	},
	{#State 10
		ACTIONS => {
			'NAME' => 22
		}
	},
	{#State 11
		ACTIONS => {
			'NAME' => 23
		}
	},
	{#State 12
		ACTIONS => {
			'NAME' => 24
		}
	},
	{#State 13
		ACTIONS => {
			'INT' => 25
		}
	},
	{#State 14
		ACTIONS => {
			":" => 26
		}
	},
	{#State 15
		ACTIONS => {
			'NAME' => 28,
			'IPA' => 27,
			'IP' => 30
		},
		GOTOS => {
			'ip' => 29
		}
	},
	{#State 16
		DEFAULT => -2
	},
	{#State 17
		DEFAULT => 0
	},
	{#State 18
		ACTIONS => {
			'NAME' => 31,
			'ICMP' => 36,
			'INT' => 33,
			'TCP' => 37,
			'UDP' => 35
		},
		GOTOS => {
			'proto' => 32,
			'prot' => 34
		}
	},
	{#State 19
		ACTIONS => {
			'STRING' => 38
		}
	},
	{#State 20
		ACTIONS => {
			'NAME' => 39,
			'STRING' => 40
		},
		GOTOS => {
			'intf1' => 41
		}
	},
	{#State 21
		ACTIONS => {
			'NAME' => 28,
			'IPA' => 27,
			'IP' => 30
		},
		GOTOS => {
			'ip' => 42
		}
	},
	{#State 22
		ACTIONS => {
			'NAME' => 43,
			'IPA' => 27,
			'IP' => 30
		},
		GOTOS => {
			'ip' => 44,
			'lan' => 45
		}
	},
	{#State 23
		ACTIONS => {
			'NAME' => 39,
			'STRING' => 40
		},
		GOTOS => {
			'intf1' => 46
		}
	},
	{#State 24
		ACTIONS => {
			":" => 47,
			'NAME' => 48,
			'INT' => 49
		},
		GOTOS => {
			'port' => 50,
			'pn' => 51
		}
	},
	{#State 25
		ACTIONS => {
			";" => 52
		}
	},
	{#State 26
		ACTIONS => {
			'ICMPTYPE' => 1,
			'HOST' => 3,
			'REDIRECT' => 53,
			'PROTO' => 6,
			'MACRO' => 7,
			'IF' => 8,
			'IP' => 9,
			'MASQU' => 59,
			'LAN' => 10,
			'IFLAN' => 11,
			'PORT' => 12,
			'RAW' => 54
		},
		DEFAULT => -54,
		GOTOS => {
			'natdef' => 55,
			'natdefs' => 56,
			'nraw' => 58,
			'define' => 57,
			'raw' => 60
		}
	},
	{#State 27
		DEFAULT => -21
	},
	{#State 28
		DEFAULT => -20
	},
	{#State 29
		ACTIONS => {
			";" => 61
		}
	},
	{#State 30
		ACTIONS => {
			"(" => 62
		}
	},
	{#State 31
		DEFAULT => -45
	},
	{#State 32
		ACTIONS => {
			";" => 63
		}
	},
	{#State 33
		DEFAULT => -44
	},
	{#State 34
		DEFAULT => -42
	},
	{#State 35
		DEFAULT => -41
	},
	{#State 36
		DEFAULT => -43
	},
	{#State 37
		DEFAULT => -40
	},
	{#State 38
		ACTIONS => {
			";" => 64
		}
	},
	{#State 39
		DEFAULT => -13
	},
	{#State 40
		DEFAULT => -14
	},
	{#State 41
		ACTIONS => {
			";" => 65
		}
	},
	{#State 42
		ACTIONS => {
			";" => 66
		}
	},
	{#State 43
		ACTIONS => {
			"/" => -20
		},
		DEFAULT => -18
	},
	{#State 44
		ACTIONS => {
			"/" => 67
		}
	},
	{#State 45
		ACTIONS => {
			";" => 68
		}
	},
	{#State 46
		ACTIONS => {
			'NAME' => 43,
			'IPA' => 27,
			'IP' => 30
		},
		GOTOS => {
			'ip' => 44,
			'lan' => 69
		}
	},
	{#State 47
		ACTIONS => {
			'INT' => 70
		}
	},
	{#State 48
		DEFAULT => -35
	},
	{#State 49
		ACTIONS => {
			":" => 71
		},
		DEFAULT => -36
	},
	{#State 50
		ACTIONS => {
			";" => 72
		}
	},
	{#State 51
		ACTIONS => {
			"," => 73
		},
		DEFAULT => -34
	},
	{#State 52
		DEFAULT => -12
	},
	{#State 53
		ACTIONS => {
			'NAME' => 78,
			'IPA' => 27,
			"!" => 75,
			'IP' => 80,
			'ANY' => 76
		},
		GOTOS => {
			'ippp' => 79,
			'ip' => 74,
			'ipp' => 77
		}
	},
	{#State 54
		ACTIONS => {
			'STRING' => 81
		}
	},
	{#State 55
		ACTIONS => {
			'ICMPTYPE' => 1,
			'HOST' => 3,
			'REDIRECT' => 53,
			'PROTO' => 6,
			'MACRO' => 7,
			'IF' => 8,
			'IP' => 9,
			'MASQU' => 59,
			'LAN' => 10,
			'IFLAN' => 11,
			'PORT' => 12,
			'RAW' => 54
		},
		DEFAULT => -54,
		GOTOS => {
			'natdef' => 55,
			'natdefs' => 82,
			'nraw' => 58,
			'define' => 57,
			'raw' => 60
		}
	},
	{#State 56
		ACTIONS => {
			'IO' => 83
		}
	},
	{#State 57
		DEFAULT => -55
	},
	{#State 58
		DEFAULT => -59
	},
	{#State 59
		ACTIONS => {
			'NAME' => 43,
			'IPA' => 27,
			'IP' => 30
		},
		GOTOS => {
			'ip' => 44,
			'lan' => 84
		}
	},
	{#State 60
		DEFAULT => -79
	},
	{#State 61
		DEFAULT => -8
	},
	{#State 62
		ACTIONS => {
			'INT' => 87,
			'EVAL' => 86
		},
		GOTOS => {
			'int' => 85
		}
	},
	{#State 63
		DEFAULT => -11
	},
	{#State 64
		DEFAULT => -4
	},
	{#State 65
		DEFAULT => -5
	},
	{#State 66
		DEFAULT => -9
	},
	{#State 67
		ACTIONS => {
			'NAME' => 28,
			'IPA' => 27,
			'INT' => 90,
			'IP' => 30
		},
		GOTOS => {
			'ip' => 88,
			'mask' => 89
		}
	},
	{#State 68
		DEFAULT => -6
	},
	{#State 69
		ACTIONS => {
			";" => 91
		}
	},
	{#State 70
		DEFAULT => -39
	},
	{#State 71
		ACTIONS => {
			'INT' => 92
		},
		DEFAULT => -38
	},
	{#State 72
		DEFAULT => -10
	},
	{#State 73
		ACTIONS => {
			":" => 47,
			'NAME' => 48,
			'INT' => 49
		},
		GOTOS => {
			'port' => 93,
			'pn' => 51
		}
	},
	{#State 74
		ACTIONS => {
			"/" => 94
		}
	},
	{#State 75
		ACTIONS => {
			'NAME' => 78,
			'IPA' => 27,
			'IP' => 80
		},
		GOTOS => {
			'ippp' => 95,
			'ip' => 74
		}
	},
	{#State 76
		DEFAULT => -109
	},
	{#State 77
		ACTIONS => {
			'TO' => 96
		}
	},
	{#State 78
		ACTIONS => {
			"/" => -20
		},
		DEFAULT => -104
	},
	{#State 79
		DEFAULT => -107
	},
	{#State 80
		ACTIONS => {
			"(" => 62
		},
		DEFAULT => -106
	},
	{#State 81
		ACTIONS => {
			";" => 97
		}
	},
	{#State 82
		DEFAULT => -53
	},
	{#State 83
		ACTIONS => {
			'REJECT' => 98,
			'DROP' => 102,
			'ACCEPT' => 99
		},
		DEFAULT => -46,
		GOTOS => {
			'pol' => 100,
			'iopol' => 101
		}
	},
	{#State 84
		ACTIONS => {
			'BY' => 103
		}
	},
	{#State 85
		ACTIONS => {
			"," => 104
		}
	},
	{#State 86
		ACTIONS => {
			"(" => 105
		}
	},
	{#State 87
		DEFAULT => -23
	},
	{#State 88
		DEFAULT => -32
	},
	{#State 89
		DEFAULT => -19
	},
	{#State 90
		DEFAULT => -31
	},
	{#State 91
		DEFAULT => -7
	},
	{#State 92
		DEFAULT => -37
	},
	{#State 93
		DEFAULT => -33
	},
	{#State 94
		ACTIONS => {
			'NAME' => 28,
			'IPA' => 27,
			'INT' => 90,
			'IP' => 30
		},
		GOTOS => {
			'ip' => 88,
			'mask' => 106
		}
	},
	{#State 95
		DEFAULT => -108
	},
	{#State 96
		ACTIONS => {
			'NAME' => 28,
			'IPA' => 27,
			'IP' => 30
		},
		GOTOS => {
			'ip' => 107
		}
	},
	{#State 97
		DEFAULT => -80
	},
	{#State 98
		DEFAULT => -52
	},
	{#State 99
		DEFAULT => -50
	},
	{#State 100
		ACTIONS => {
			"," => 108
		}
	},
	{#State 101
		ACTIONS => {
			":" => 109
		}
	},
	{#State 102
		DEFAULT => -51
	},
	{#State 103
		ACTIONS => {
			'NAME' => 39,
			"/" => 112,
			'STRING' => 40
		},
		GOTOS => {
			'intf' => 111,
			'intf1' => 110
		}
	},
	{#State 104
		ACTIONS => {
			'INT' => 87,
			'EVAL' => 86
		},
		GOTOS => {
			'int' => 113
		}
	},
	{#State 105
		ACTIONS => {
			"(" => 116,
			'INT' => 87,
			'EVAL' => 86
		},
		GOTOS => {
			'expr' => 115,
			'int' => 114
		}
	},
	{#State 106
		DEFAULT => -105
	},
	{#State 107
		ACTIONS => {
			":" => 117,
			"(" => 119
		},
		DEFAULT => -81,
		GOTOS => {
			'parms' => 118
		}
	},
	{#State 108
		ACTIONS => {
			'REJECT' => 98,
			'DROP' => 102,
			'ACCEPT' => 99
		},
		GOTOS => {
			'pol' => 120
		}
	},
	{#State 109
		ACTIONS => {
			'REJECT' => 121,
			'ACCEPT' => 122,
			'FORWARD' => -61,
			'RETURN' => 124,
			'LOG' => 125,
			'RAW' => 54,
			'NAME' => 127,
			'LOGDROP' => 128,
			'DROP' => 129,
			'SERVICE' => 131,
			'CH' => 132,
			'USE' => 134,
			'GO' => 136
		},
		DEFAULT => -125,
		GOTOS => {
			'fraw' => 133,
			'optnm' => 135,
			'iodef' => 130,
			'iodefs' => 123,
			'raw' => 137,
			'act' => 126
		}
	},
	{#State 110
		ACTIONS => {
			"/" => 138
		},
		DEFAULT => -15
	},
	{#State 111
		ACTIONS => {
			"(" => 119
		},
		DEFAULT => -81,
		GOTOS => {
			'parms' => 139
		}
	},
	{#State 112
		ACTIONS => {
			'NAME' => 39,
			'STRING' => 40
		},
		GOTOS => {
			'intf1' => 140
		}
	},
	{#State 113
		ACTIONS => {
			"," => 141
		}
	},
	{#State 114
		DEFAULT => -25
	},
	{#State 115
		ACTIONS => {
			"-" => 142,
			"*" => 144,
			"+" => 143,
			"/" => 146,
			")" => 145
		}
	},
	{#State 116
		ACTIONS => {
			"(" => 116,
			'INT' => 87,
			'EVAL' => 86
		},
		GOTOS => {
			'expr' => 147,
			'int' => 114
		}
	},
	{#State 117
		ACTIONS => {
			":" => 47,
			'NAME' => 48,
			'INT' => 49
		},
		GOTOS => {
			'port' => 148,
			'pn' => 51
		}
	},
	{#State 118
		ACTIONS => {
			";" => 149
		}
	},
	{#State 119
		ACTIONS => {
			'ICMPTYPE' => 150,
			'GROUP' => 157,
			'MY' => 151,
			'PROTO' => 152,
			'YOUR' => 159,
			'CLIENT' => 158,
			'IF' => 153,
			'IP' => 161,
			'SERVER' => 154,
			'USER' => 155,
			'PORT' => 156
		},
		DEFAULT => -84,
		GOTOS => {
			'prms' => 160,
			'parm' => 162
		}
	},
	{#State 120
		DEFAULT => -47
	},
	{#State 121
		DEFAULT => -118
	},
	{#State 122
		DEFAULT => -116
	},
	{#State 123
		ACTIONS => {
			'FORWARD' => 163
		}
	},
	{#State 124
		DEFAULT => -121
	},
	{#State 125
		DEFAULT => -119
	},
	{#State 126
		ACTIONS => {
			"(" => 119
		},
		DEFAULT => -81,
		GOTOS => {
			'parms' => 164
		}
	},
	{#State 127
		DEFAULT => -124
	},
	{#State 128
		DEFAULT => -120
	},
	{#State 129
		DEFAULT => -117
	},
	{#State 130
		ACTIONS => {
			'REJECT' => 121,
			'ACCEPT' => 122,
			'RETURN' => 124,
			'LOG' => 125,
			'RAW' => 54,
			'NAME' => 127,
			'LOGDROP' => 128,
			'DROP' => 129,
			"{" => -125,
			'SERVICE' => 131,
			'CH' => 132,
			'USE' => 134,
			"(" => -125,
			'GO' => 136
		},
		DEFAULT => -61,
		GOTOS => {
			'fraw' => 133,
			'optnm' => 135,
			'iodef' => 130,
			'iodefs' => 165,
			'raw' => 137,
			'act' => 126
		}
	},
	{#State 131
		DEFAULT => -123
	},
	{#State 132
		ACTIONS => {
			'NAME' => 166
		}
	},
	{#State 133
		DEFAULT => -68
	},
	{#State 134
		DEFAULT => -122
	},
	{#State 135
		ACTIONS => {
			"(" => 119
		},
		DEFAULT => -81,
		GOTOS => {
			'parms' => 167
		}
	},
	{#State 136
		ACTIONS => {
			'NAME' => 168
		}
	},
	{#State 137
		DEFAULT => -78
	},
	{#State 138
		ACTIONS => {
			'NAME' => 39,
			'STRING' => 40
		},
		GOTOS => {
			'intf1' => 169
		}
	},
	{#State 139
		ACTIONS => {
			";" => 170
		}
	},
	{#State 140
		DEFAULT => -17
	},
	{#State 141
		ACTIONS => {
			'INT' => 87,
			'EVAL' => 86
		},
		GOTOS => {
			'int' => 171
		}
	},
	{#State 142
		ACTIONS => {
			"(" => 116,
			'INT' => 87,
			'EVAL' => 86
		},
		GOTOS => {
			'expr' => 172,
			'int' => 114
		}
	},
	{#State 143
		ACTIONS => {
			"(" => 116,
			'INT' => 87,
			'EVAL' => 86
		},
		GOTOS => {
			'expr' => 173,
			'int' => 114
		}
	},
	{#State 144
		ACTIONS => {
			"(" => 116,
			'INT' => 87,
			'EVAL' => 86
		},
		GOTOS => {
			'expr' => 174,
			'int' => 114
		}
	},
	{#State 145
		DEFAULT => -24
	},
	{#State 146
		ACTIONS => {
			"(" => 116,
			'INT' => 87,
			'EVAL' => 86
		},
		GOTOS => {
			'expr' => 175,
			'int' => 114
		}
	},
	{#State 147
		ACTIONS => {
			"-" => 142,
			"*" => 144,
			"+" => 143,
			"/" => 146,
			")" => 176
		}
	},
	{#State 148
		ACTIONS => {
			"(" => 119
		},
		DEFAULT => -81,
		GOTOS => {
			'parms' => 177
		}
	},
	{#State 149
		DEFAULT => -56
	},
	{#State 150
		ACTIONS => {
			'NAME' => 178,
			'INT' => 179
		},
		GOTOS => {
			'icmpt' => 180
		}
	},
	{#State 151
		ACTIONS => {
			'IP' => 182,
			'PORT' => 181
		}
	},
	{#State 152
		ACTIONS => {
			'NAME' => 31,
			'ICMP' => 36,
			'INT' => 33,
			'TCP' => 37,
			'UDP' => 35
		},
		GOTOS => {
			'protos' => 184,
			'proto' => 183,
			'prot' => 34
		}
	},
	{#State 153
		ACTIONS => {
			'NAME' => 39,
			"!" => 185,
			"/" => 112,
			'ANY' => 186,
			'STRING' => 40
		},
		GOTOS => {
			'ifp' => 188,
			'intf' => 187,
			'intf1' => 110
		}
	},
	{#State 154
		ACTIONS => {
			'NAME' => 78,
			'IPA' => 27,
			"!" => 75,
			'IP' => 80,
			'ANY' => 76
		},
		GOTOS => {
			'ippp' => 79,
			'ip' => 74,
			'ipp' => 189
		}
	},
	{#State 155
		ACTIONS => {
			'NAME' => 190
		}
	},
	{#State 156
		ACTIONS => {
			":" => 47,
			'NAME' => 48,
			'INT' => 49,
			'ANY' => 191
		},
		GOTOS => {
			'portp' => 192,
			'port' => 193,
			'pn' => 51
		}
	},
	{#State 157
		ACTIONS => {
			'NAME' => 194
		}
	},
	{#State 158
		ACTIONS => {
			'NAME' => 78,
			'IPA' => 27,
			"!" => 75,
			'IP' => 80,
			'ANY' => 76
		},
		GOTOS => {
			'ippp' => 79,
			'ip' => 74,
			'ipp' => 195
		}
	},
	{#State 159
		ACTIONS => {
			'IP' => 197,
			'PORT' => 196
		}
	},
	{#State 160
		ACTIONS => {
			")" => 198
		}
	},
	{#State 161
		ACTIONS => {
			'NAME' => 78,
			'IPA' => 27,
			"!" => 75,
			'IP' => 80,
			'ANY' => 76
		},
		GOTOS => {
			'ippp' => 79,
			'ip' => 74,
			'ipp' => 199
		}
	},
	{#State 162
		ACTIONS => {
			'ICMPTYPE' => 150,
			'GROUP' => 157,
			'MY' => 151,
			'PROTO' => 152,
			'YOUR' => 159,
			'CLIENT' => 158,
			'IF' => 153,
			'IP' => 161,
			'SERVER' => 154,
			'USER' => 155,
			'PORT' => 156
		},
		DEFAULT => -84,
		GOTOS => {
			'prms' => 200,
			'parm' => 162
		}
	},
	{#State 163
		ACTIONS => {
			'REJECT' => 98,
			'DROP' => 102,
			'ACCEPT' => 99
		},
		DEFAULT => -48,
		GOTOS => {
			'pol' => 201,
			'fwpol' => 202
		}
	},
	{#State 164
		ACTIONS => {
			";" => 203
		}
	},
	{#State 165
		DEFAULT => -60
	},
	{#State 166
		ACTIONS => {
			"{" => 204
		}
	},
	{#State 167
		ACTIONS => {
			"{" => 205
		}
	},
	{#State 168
		ACTIONS => {
			"(" => 119
		},
		DEFAULT => -81,
		GOTOS => {
			'parms' => 206
		}
	},
	{#State 169
		DEFAULT => -16
	},
	{#State 170
		DEFAULT => -58
	},
	{#State 171
		ACTIONS => {
			"," => 207
		}
	},
	{#State 172
		ACTIONS => {
			"*" => 144,
			"/" => 146
		},
		DEFAULT => -27
	},
	{#State 173
		ACTIONS => {
			"*" => 144,
			"/" => 146
		},
		DEFAULT => -26
	},
	{#State 174
		DEFAULT => -28
	},
	{#State 175
		DEFAULT => -29
	},
	{#State 176
		DEFAULT => -30
	},
	{#State 177
		ACTIONS => {
			";" => 208
		}
	},
	{#State 178
		DEFAULT => -111
	},
	{#State 179
		DEFAULT => -110
	},
	{#State 180
		ACTIONS => {
			";" => 209
		}
	},
	{#State 181
		ACTIONS => {
			":" => 47,
			'NAME' => 48,
			'INT' => 49,
			'ANY' => 191
		},
		GOTOS => {
			'portp' => 210,
			'port' => 211,
			'pn' => 51
		}
	},
	{#State 182
		ACTIONS => {
			'NAME' => 78,
			'IPA' => 27,
			"!" => 75,
			'IP' => 80,
			'ANY' => 76
		},
		GOTOS => {
			'ippp' => 79,
			'ip' => 74,
			'ipp' => 212
		}
	},
	{#State 183
		ACTIONS => {
			"," => 213
		},
		DEFAULT => -115
	},
	{#State 184
		ACTIONS => {
			";" => 214
		}
	},
	{#State 185
		ACTIONS => {
			'NAME' => 39,
			"/" => 112,
			'STRING' => 40
		},
		GOTOS => {
			'intf' => 215,
			'intf1' => 110
		}
	},
	{#State 186
		DEFAULT => -103
	},
	{#State 187
		DEFAULT => -101
	},
	{#State 188
		ACTIONS => {
			";" => 216,
			'TO' => 217
		}
	},
	{#State 189
		ACTIONS => {
			";" => 218
		}
	},
	{#State 190
		ACTIONS => {
			";" => 219
		}
	},
	{#State 191
		DEFAULT => -113
	},
	{#State 192
		ACTIONS => {
			'TO' => 220
		}
	},
	{#State 193
		ACTIONS => {
			";" => 221
		},
		DEFAULT => -112
	},
	{#State 194
		ACTIONS => {
			";" => 222
		}
	},
	{#State 195
		ACTIONS => {
			";" => 223
		}
	},
	{#State 196
		ACTIONS => {
			":" => 47,
			'NAME' => 48,
			'INT' => 49,
			'ANY' => 191
		},
		GOTOS => {
			'portp' => 224,
			'port' => 211,
			'pn' => 51
		}
	},
	{#State 197
		ACTIONS => {
			'NAME' => 78,
			'IPA' => 27,
			"!" => 75,
			'IP' => 80,
			'ANY' => 76
		},
		GOTOS => {
			'ippp' => 79,
			'ip' => 74,
			'ipp' => 225
		}
	},
	{#State 198
		DEFAULT => -82
	},
	{#State 199
		ACTIONS => {
			";" => 226,
			'TO' => 227
		}
	},
	{#State 200
		DEFAULT => -83
	},
	{#State 201
		DEFAULT => -49
	},
	{#State 202
		ACTIONS => {
			":" => 228
		}
	},
	{#State 203
		DEFAULT => -62
	},
	{#State 204
		DEFAULT => -64,
		GOTOS => {
			'@1-3' => 229
		}
	},
	{#State 205
		DEFAULT => -66,
		GOTOS => {
			'@2-3' => 230
		}
	},
	{#State 206
		ACTIONS => {
			";" => 231
		}
	},
	{#State 207
		ACTIONS => {
			'INT' => 87,
			'EVAL' => 86
		},
		GOTOS => {
			'int' => 232
		}
	},
	{#State 208
		DEFAULT => -57
	},
	{#State 209
		DEFAULT => -98
	},
	{#State 210
		ACTIONS => {
			";" => 233
		}
	},
	{#State 211
		DEFAULT => -112
	},
	{#State 212
		ACTIONS => {
			";" => 234
		}
	},
	{#State 213
		ACTIONS => {
			'NAME' => 31,
			'ICMP' => 36,
			'INT' => 33,
			'TCP' => 37,
			'UDP' => 35
		},
		GOTOS => {
			'protos' => 235,
			'proto' => 183,
			'prot' => 34
		}
	},
	{#State 214
		DEFAULT => -92
	},
	{#State 215
		DEFAULT => -102
	},
	{#State 216
		DEFAULT => -85
	},
	{#State 217
		ACTIONS => {
			'NAME' => 39,
			"!" => 185,
			"/" => 112,
			'ANY' => 186,
			'STRING' => 40
		},
		GOTOS => {
			'ifp' => 236,
			'intf' => 187,
			'intf1' => 110
		}
	},
	{#State 218
		DEFAULT => -96
	},
	{#State 219
		DEFAULT => -99
	},
	{#State 220
		ACTIONS => {
			":" => 47,
			'NAME' => 48,
			'INT' => 49,
			'ANY' => 191
		},
		GOTOS => {
			'portp' => 237,
			'port' => 211,
			'pn' => 51
		}
	},
	{#State 221
		DEFAULT => -91
	},
	{#State 222
		DEFAULT => -100
	},
	{#State 223
		DEFAULT => -97
	},
	{#State 224
		ACTIONS => {
			";" => 238
		}
	},
	{#State 225
		ACTIONS => {
			";" => 239
		}
	},
	{#State 226
		DEFAULT => -87
	},
	{#State 227
		ACTIONS => {
			'NAME' => 78,
			'IPA' => 27,
			"!" => 75,
			'IP' => 80,
			'ANY' => 76
		},
		GOTOS => {
			'ippp' => 79,
			'ip' => 74,
			'ipp' => 240
		}
	},
	{#State 228
		ACTIONS => {
			'' => -70,
			'REJECT' => 121,
			'ACCEPT' => 122,
			'RETURN' => 124,
			'LOG' => 125,
			'RAW' => 54,
			'NAME' => 127,
			'LOGDROP' => 128,
			'DROP' => 129,
			'SERVICE' => 131,
			'CH' => 243,
			'USE' => 134,
			'GO' => 246
		},
		DEFAULT => -125,
		GOTOS => {
			'fraw' => 244,
			'optnm' => 245,
			'fwdef' => 242,
			'fwdefs' => 247,
			'raw' => 137,
			'act' => 241
		}
	},
	{#State 229
		ACTIONS => {
			"}" => -61,
			'REJECT' => 121,
			'ACCEPT' => 122,
			'RETURN' => 124,
			'LOG' => 125,
			'RAW' => 54,
			'NAME' => 127,
			'LOGDROP' => 128,
			'DROP' => 129,
			'SERVICE' => 131,
			'CH' => 132,
			'USE' => 134,
			'GO' => 136
		},
		DEFAULT => -125,
		GOTOS => {
			'fraw' => 133,
			'optnm' => 135,
			'iodef' => 130,
			'iodefs' => 248,
			'raw' => 137,
			'act' => 126
		}
	},
	{#State 230
		ACTIONS => {
			"}" => -61,
			'REJECT' => 121,
			'ACCEPT' => 122,
			'RETURN' => 124,
			'LOG' => 125,
			'RAW' => 54,
			'NAME' => 127,
			'LOGDROP' => 128,
			'DROP' => 129,
			'SERVICE' => 131,
			'CH' => 132,
			'USE' => 134,
			'GO' => 136
		},
		DEFAULT => -125,
		GOTOS => {
			'fraw' => 133,
			'optnm' => 135,
			'iodef' => 130,
			'iodefs' => 249,
			'raw' => 137,
			'act' => 126
		}
	},
	{#State 231
		DEFAULT => -63
	},
	{#State 232
		ACTIONS => {
			")" => 250
		}
	},
	{#State 233
		DEFAULT => -94
	},
	{#State 234
		DEFAULT => -90
	},
	{#State 235
		DEFAULT => -114
	},
	{#State 236
		ACTIONS => {
			";" => 251
		}
	},
	{#State 237
		ACTIONS => {
			";" => 252
		}
	},
	{#State 238
		DEFAULT => -95
	},
	{#State 239
		DEFAULT => -89
	},
	{#State 240
		ACTIONS => {
			";" => 253
		}
	},
	{#State 241
		ACTIONS => {
			"(" => 119
		},
		DEFAULT => -81,
		GOTOS => {
			'parms' => 254
		}
	},
	{#State 242
		ACTIONS => {
			'REJECT' => 121,
			'ACCEPT' => 122,
			'RETURN' => 124,
			'LOG' => 125,
			'RAW' => 54,
			'NAME' => 127,
			'LOGDROP' => 128,
			'DROP' => 129,
			"{" => -125,
			'SERVICE' => 131,
			'CH' => 243,
			'USE' => 134,
			"(" => -125,
			'GO' => 246
		},
		DEFAULT => -70,
		GOTOS => {
			'fraw' => 244,
			'optnm' => 245,
			'fwdef' => 242,
			'fwdefs' => 255,
			'raw' => 137,
			'act' => 241
		}
	},
	{#State 243
		ACTIONS => {
			'NAME' => 256
		}
	},
	{#State 244
		DEFAULT => -77
	},
	{#State 245
		ACTIONS => {
			"(" => 119
		},
		DEFAULT => -81,
		GOTOS => {
			'parms' => 257
		}
	},
	{#State 246
		ACTIONS => {
			'NAME' => 258
		}
	},
	{#State 247
		DEFAULT => -1
	},
	{#State 248
		ACTIONS => {
			"}" => 259
		}
	},
	{#State 249
		ACTIONS => {
			"}" => 260
		}
	},
	{#State 250
		DEFAULT => -22
	},
	{#State 251
		DEFAULT => -86
	},
	{#State 252
		DEFAULT => -93
	},
	{#State 253
		DEFAULT => -88
	},
	{#State 254
		ACTIONS => {
			";" => 261
		}
	},
	{#State 255
		DEFAULT => -69
	},
	{#State 256
		ACTIONS => {
			"{" => 262
		}
	},
	{#State 257
		ACTIONS => {
			"{" => 263
		}
	},
	{#State 258
		ACTIONS => {
			"(" => 119
		},
		DEFAULT => -81,
		GOTOS => {
			'parms' => 264
		}
	},
	{#State 259
		DEFAULT => -65
	},
	{#State 260
		DEFAULT => -67
	},
	{#State 261
		DEFAULT => -71
	},
	{#State 262
		DEFAULT => -73,
		GOTOS => {
			'@3-3' => 265
		}
	},
	{#State 263
		DEFAULT => -75,
		GOTOS => {
			'@4-3' => 266
		}
	},
	{#State 264
		ACTIONS => {
			";" => 267
		}
	},
	{#State 265
		ACTIONS => {
			"}" => -70,
			'REJECT' => 121,
			'ACCEPT' => 122,
			'RETURN' => 124,
			'LOG' => 125,
			'RAW' => 54,
			'NAME' => 127,
			'LOGDROP' => 128,
			'DROP' => 129,
			'SERVICE' => 131,
			'CH' => 243,
			'USE' => 134,
			'GO' => 246
		},
		DEFAULT => -125,
		GOTOS => {
			'fraw' => 244,
			'optnm' => 245,
			'fwdef' => 242,
			'fwdefs' => 268,
			'raw' => 137,
			'act' => 241
		}
	},
	{#State 266
		ACTIONS => {
			"}" => -70,
			'REJECT' => 121,
			'ACCEPT' => 122,
			'RETURN' => 124,
			'LOG' => 125,
			'RAW' => 54,
			'NAME' => 127,
			'LOGDROP' => 128,
			'DROP' => 129,
			'SERVICE' => 131,
			'CH' => 243,
			'USE' => 134,
			'GO' => 246
		},
		DEFAULT => -125,
		GOTOS => {
			'fraw' => 244,
			'optnm' => 245,
			'fwdef' => 242,
			'fwdefs' => 269,
			'raw' => 137,
			'act' => 241
		}
	},
	{#State 267
		DEFAULT => -72
	},
	{#State 268
		ACTIONS => {
			"}" => 270
		}
	},
	{#State 269
		ACTIONS => {
			"}" => 271
		}
	},
	{#State 270
		DEFAULT => -74
	},
	{#State 271
		DEFAULT => -76
	}
],
                                  yyrules  =>
[
	[#Rule 0
		 '$start', 2, undef
	],
	[#Rule 1
		 'all', 12, undef
	],
	[#Rule 2
		 'defines', 2, undef
	],
	[#Rule 3
		 'defines', 0, undef
	],
	[#Rule 4
		 'define', 4,
sub
#line 576 "iptcon.py"
{ $macros{$_[2]} = $_[3]; }
	],
	[#Rule 5
		 'define', 4,
sub
#line 577 "iptcon.py"
{ $ifs{$_[2]}    = $_[3]; }
	],
	[#Rule 6
		 'define', 4,
sub
#line 578 "iptcon.py"
{ $lans{$_[2]}   = $_[3]; }
	],
	[#Rule 7
		 'define', 5,
sub
#line 579 "iptcon.py"
{ $ifs{$_[2]."if"} = $_[3];
                                          $lans{$_[2]."lan"} = $_[4];
                                          $ips{$_[2]."ip"} = &ipmsk($_[4], $_[3]); }
	],
	[#Rule 8
		 'define', 4,
sub
#line 582 "iptcon.py"
{ $ips{$_[2]}    = $_[3]; }
	],
	[#Rule 9
		 'define', 4,
sub
#line 583 "iptcon.py"
{ $ips{$_[2]}    = $_[3]; }
	],
	[#Rule 10
		 'define', 4,
sub
#line 584 "iptcon.py"
{ $ports{$_[2]}  = $_[3]; }
	],
	[#Rule 11
		 'define', 4,
sub
#line 585 "iptcon.py"
{ $protos{$_[2]} = $_[3]; }
	],
	[#Rule 12
		 'define', 4,
sub
#line 586 "iptcon.py"
{ $icmpts{$_[2]} = $_[3]; }
	],
	[#Rule 13
		 'intf1', 1,
sub
#line 588 "iptcon.py"
{ defined($ifs{$_[1]})  ? $ifs{$_[1]} : &__error("Undefined interface: $_[1]"); }
	],
	[#Rule 14
		 'intf1', 1,
sub
#line 589 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 15
		 'intf', 1,
sub
#line 591 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 16
		 'intf', 3,
sub
#line 592 "iptcon.py"
{ $_[1] . '/' . $_[3]; }
	],
	[#Rule 17
		 'intf', 2,
sub
#line 593 "iptcon.py"
{ '/' . $_[2]; }
	],
	[#Rule 18
		 'lan', 1,
sub
#line 595 "iptcon.py"
{ defined($lans{$_[1]}) ? $lans{$_[1]} : &__error("Undefined lan: $_[1]"); }
	],
	[#Rule 19
		 'lan', 3,
sub
#line 596 "iptcon.py"
{ "$_[1]/$_[3]"; }
	],
	[#Rule 20
		 'ip', 1,
sub
#line 598 "iptcon.py"
{ defined($ips{$_[1]})  ? $ips{$_[1]} : &__error("Undefined ip: $_[1]"); }
	],
	[#Rule 21
		 'ip', 1,
sub
#line 599 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 22
		 'ip', 10,
sub
#line 601 "iptcon.py"
{ $_[3] . '.' . $_[5] . '.' . $_[7] . '.' .$_[9]; }
	],
	[#Rule 23
		 'int', 1,
sub
#line 603 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 24
		 'int', 4,
sub
#line 604 "iptcon.py"
{ $_[3]; }
	],
	[#Rule 25
		 'expr', 1,
sub
#line 606 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 26
		 'expr', 3,
sub
#line 607 "iptcon.py"
{ $_[1] + $_[3]; }
	],
	[#Rule 27
		 'expr', 3,
sub
#line 608 "iptcon.py"
{ $_[1] - $_[3]; }
	],
	[#Rule 28
		 'expr', 3,
sub
#line 609 "iptcon.py"
{ $_[1] * $_[3]; }
	],
	[#Rule 29
		 'expr', 3,
sub
#line 610 "iptcon.py"
{ $_[1] / $_[3]; }
	],
	[#Rule 30
		 'expr', 3,
sub
#line 611 "iptcon.py"
{ $_[2]; }
	],
	[#Rule 31
		 'mask', 1,
sub
#line 613 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 32
		 'mask', 1,
sub
#line 614 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 33
		 'port', 3,
sub
#line 616 "iptcon.py"
{ "$_[1],$_[3]"; }
	],
	[#Rule 34
		 'port', 1,
sub
#line 617 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 35
		 'pn', 1,
sub
#line 619 "iptcon.py"
{ defined($ports{$_[1]}) ? $ports{$_[1]} :
					      &chkservice($_[1]) ? &chkservice($_[1]) :
						                   &__error("Undefined service: $_[1]"); }
	],
	[#Rule 36
		 'pn', 1,
sub
#line 622 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 37
		 'pn', 3,
sub
#line 623 "iptcon.py"
{ "$_[1]:$_[3]"; }
	],
	[#Rule 38
		 'pn', 2,
sub
#line 624 "iptcon.py"
{ "$_[1]:"; }
	],
	[#Rule 39
		 'pn', 2,
sub
#line 625 "iptcon.py"
{ ":$_[2]"; }
	],
	[#Rule 40
		 'prot', 1,
sub
#line 627 "iptcon.py"
{ 'tcp'; }
	],
	[#Rule 41
		 'prot', 1,
sub
#line 628 "iptcon.py"
{ 'udp'; }
	],
	[#Rule 42
		 'proto', 1,
sub
#line 630 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 43
		 'proto', 1,
sub
#line 631 "iptcon.py"
{ 'icmp'; }
	],
	[#Rule 44
		 'proto', 1,
sub
#line 632 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 45
		 'proto', 1,
sub
#line 633 "iptcon.py"
{ defined($protos{$_[1]})  ? $protos{$_[1]} : &__error("Undefined protocol: $_[1]"); }
	],
	[#Rule 46
		 'iopol', 0, undef
	],
	[#Rule 47
		 'iopol', 3,
sub
#line 636 "iptcon.py"
{ $pol{'INPUT'} = $_[1]; $pol{'OUTPUT'} = $_[3]; }
	],
	[#Rule 48
		 'fwpol', 0, undef
	],
	[#Rule 49
		 'fwpol', 1,
sub
#line 639 "iptcon.py"
{ $pol{'FORWARD'} = $_[1];}
	],
	[#Rule 50
		 'pol', 1,
sub
#line 641 "iptcon.py"
{ 'ACCEPT'; }
	],
	[#Rule 51
		 'pol', 1,
sub
#line 642 "iptcon.py"
{ 'DROP'; }
	],
	[#Rule 52
		 'pol', 1,
sub
#line 643 "iptcon.py"
{ 'REJECT'; }
	],
	[#Rule 53
		 'natdefs', 2, undef
	],
	[#Rule 54
		 'natdefs', 0, undef
	],
	[#Rule 55
		 'natdef', 1, undef
	],
	[#Rule 56
		 'natdef', 6,
sub
#line 650 "iptcon.py"
{ &redirect($_[2], $_[4], '',    $_[5]); }
	],
	[#Rule 57
		 'natdef', 8,
sub
#line 652 "iptcon.py"
{ &redirect($_[2], $_[4], $_[6], $_[7]); }
	],
	[#Rule 58
		 'natdef', 6,
sub
#line 653 "iptcon.py"
{ &masqu($_[2], $_[4], $_[5]); }
	],
	[#Rule 59
		 'natdef', 1, undef
	],
	[#Rule 60
		 'iodefs', 2, undef
	],
	[#Rule 61
		 'iodefs', 0, undef
	],
	[#Rule 62
		 'iodef', 3,
sub
#line 659 "iptcon.py"
{ &act('IO', $_[1], $_[2]); }
	],
	[#Rule 63
		 'iodef', 4,
sub
#line 660 "iptcon.py"
{ &act('IO', $_[2], $_[3]); }
	],
	[#Rule 64
		 '@1-3', 0,
sub
#line 661 "iptcon.py"
{ &ch($_[2]); }
	],
	[#Rule 65
		 'iodef', 6,
sub
#line 663 "iptcon.py"
{ pop(@chst); }
	],
	[#Rule 66
		 '@2-3', 0,
sub
#line 664 "iptcon.py"
{ &act('IO', $_[1], $_[2]); &ch($_[1]); }
	],
	[#Rule 67
		 'iodef', 6,
sub
#line 666 "iptcon.py"
{ pop(@chst); }
	],
	[#Rule 68
		 'iodef', 1, undef
	],
	[#Rule 69
		 'fwdefs', 2, undef
	],
	[#Rule 70
		 'fwdefs', 0, undef
	],
	[#Rule 71
		 'fwdef', 3,
sub
#line 672 "iptcon.py"
{ &act('FW', $_[1], $_[2]); }
	],
	[#Rule 72
		 'fwdef', 4,
sub
#line 673 "iptcon.py"
{ &act('FW', $_[2], $_[3]); }
	],
	[#Rule 73
		 '@3-3', 0,
sub
#line 674 "iptcon.py"
{ &ch($_[2]); }
	],
	[#Rule 74
		 'fwdef', 6,
sub
#line 676 "iptcon.py"
{ pop(@chst); }
	],
	[#Rule 75
		 '@4-3', 0,
sub
#line 677 "iptcon.py"
{ &act('FW', $_[1], $_[2]); &ch($_[1]); }
	],
	[#Rule 76
		 'fwdef', 6,
sub
#line 679 "iptcon.py"
{ pop(@chst); }
	],
	[#Rule 77
		 'fwdef', 1, undef
	],
	[#Rule 78
		 'fraw', 1,
sub
#line 682 "iptcon.py"
{ $filt .= "$_[1]"; }
	],
	[#Rule 79
		 'nraw', 1,
sub
#line 684 "iptcon.py"
{ $nat .= "$_[1]"; }
	],
	[#Rule 80
		 'raw', 3,
sub
#line 686 "iptcon.py"
{ raw($_[2]); }
	],
	[#Rule 81
		 'parms', 0,
sub
#line 688 "iptcon.py"
{ \%null; }
	],
	[#Rule 82
		 'parms', 3,
sub
#line 689 "iptcon.py"
{ $_[2]; }
	],
	[#Rule 83
		 'prms', 2,
sub
#line 691 "iptcon.py"
{ hashcat($_[1],$_[2]); }
	],
	[#Rule 84
		 'prms', 0,
sub
#line 692 "iptcon.py"
{ \%null; }
	],
	[#Rule 85
		 'parm', 3,
sub
#line 694 "iptcon.py"
{ {'IF'       => $_[2] }; }
	],
	[#Rule 86
		 'parm', 5,
sub
#line 695 "iptcon.py"
{ {'IFTO'     => "$_[2];$_[4]" }; }
	],
	[#Rule 87
		 'parm', 3,
sub
#line 696 "iptcon.py"
{ {'IP'       => $_[2] }; }
	],
	[#Rule 88
		 'parm', 5,
sub
#line 697 "iptcon.py"
{ {'IPTO'     => "$_[2];$_[4]" }; }
	],
	[#Rule 89
		 'parm', 4,
sub
#line 698 "iptcon.py"
{ {'YOURIP'   => $_[3] }; }
	],
	[#Rule 90
		 'parm', 4,
sub
#line 699 "iptcon.py"
{ {'MYIP'     => $_[3] }; }
	],
	[#Rule 91
		 'parm', 3,
sub
#line 700 "iptcon.py"
{ {'PORT'     => $_[2] }; }
	],
	[#Rule 92
		 'parm', 3,
sub
#line 701 "iptcon.py"
{ {'PROTO'    => $_[2] }; }
	],
	[#Rule 93
		 'parm', 5,
sub
#line 702 "iptcon.py"
{ {'PORTTO'   => "$_[2];$_[4]" }; }
	],
	[#Rule 94
		 'parm', 4,
sub
#line 703 "iptcon.py"
{ {'MYPORT'   => $_[3] }; }
	],
	[#Rule 95
		 'parm', 4,
sub
#line 704 "iptcon.py"
{ {'YOURPORT' => $_[3] }; }
	],
	[#Rule 96
		 'parm', 3,
sub
#line 705 "iptcon.py"
{ {'SERVER'   => $_[2] }; }
	],
	[#Rule 97
		 'parm', 3,
sub
#line 706 "iptcon.py"
{ {'CLIENT'   => $_[2] }; }
	],
	[#Rule 98
		 'parm', 3,
sub
#line 707 "iptcon.py"
{ {'ICMPT'    => $_[2] }; }
	],
	[#Rule 99
		 'parm', 3,
sub
#line 708 "iptcon.py"
{ {'USER'     => $_[2] }; }
	],
	[#Rule 100
		 'parm', 3,
sub
#line 709 "iptcon.py"
{ {'GROUP'    => $_[2] }; }
	],
	[#Rule 101
		 'ifp', 1,
sub
#line 711 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 102
		 'ifp', 2,
sub
#line 712 "iptcon.py"
{ "! $_[2]"; }
	],
	[#Rule 103
		 'ifp', 1,
sub
#line 713 "iptcon.py"
{ ''; }
	],
	[#Rule 104
		 'ippp', 1,
sub
#line 715 "iptcon.py"
{ defined($ips{$_[1]})  ? $ips{$_[1]} :
                                          defined($lans{$_[1]}) ? $lans{$_[1]} : &__error("Undefined lan or ip: $_[1]"); ; }
	],
	[#Rule 105
		 'ippp', 3,
sub
#line 717 "iptcon.py"
{ "$_[1]/$_[3]"; }
	],
	[#Rule 106
		 'ippp', 1,
sub
#line 718 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 107
		 'ipp', 1,
sub
#line 720 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 108
		 'ipp', 2,
sub
#line 721 "iptcon.py"
{ "! $_[2]"; }
	],
	[#Rule 109
		 'ipp', 1,
sub
#line 722 "iptcon.py"
{ ''; }
	],
	[#Rule 110
		 'icmpt', 1,
sub
#line 724 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 111
		 'icmpt', 1,
sub
#line 725 "iptcon.py"
{ defined($icmpts{$_[1]})  ? $icmpts{$_[1]} : &__error("Undefined icmp type: $_[1]"); }
	],
	[#Rule 112
		 'portp', 1,
sub
#line 727 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 113
		 'portp', 1,
sub
#line 728 "iptcon.py"
{ ''; }
	],
	[#Rule 114
		 'protos', 3,
sub
#line 730 "iptcon.py"
{ "$_[1],$_[3]"; }
	],
	[#Rule 115
		 'protos', 1,
sub
#line 731 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 116
		 'act', 1,
sub
#line 733 "iptcon.py"
{ 'ACCEPT';  }
	],
	[#Rule 117
		 'act', 1,
sub
#line 734 "iptcon.py"
{ 'DROP';    }
	],
	[#Rule 118
		 'act', 1,
sub
#line 735 "iptcon.py"
{ 'REJECT';  }
	],
	[#Rule 119
		 'act', 1,
sub
#line 736 "iptcon.py"
{ 'LOG';     }
	],
	[#Rule 120
		 'act', 1,
sub
#line 737 "iptcon.py"
{ 'logdrop'; }
	],
	[#Rule 121
		 'act', 1,
sub
#line 738 "iptcon.py"
{ 'RETURN';  }
	],
	[#Rule 122
		 'act', 1,
sub
#line 739 "iptcon.py"
{ 'USE';    }
	],
	[#Rule 123
		 'act', 1,
sub
#line 740 "iptcon.py"
{ 'SERVICE'; }
	],
	[#Rule 124
		 'optnm', 1,
sub
#line 742 "iptcon.py"
{ $_[1]; }
	],
	[#Rule 125
		 'optnm', 0,
sub
#line 743 "iptcon.py"
{ $cnt++, "an${cnt}x"; }
	]
],
                                  @_);
    bless($self,$class);
}

#line 745 "iptcon.py"


sub _Error {
    print STDERR "Error in line : $.\n";
    if (exists $_[0]->YYData->{ERRMSG}) {
        print STDERR $_[0]->YYData->{ERRMSG};
        delete $_[0]->YYData->{ERRMSG};
    }
    else {
	print STDERR "Syntax error.\n";
    }
    $_[0]->{ErrStat} = 1;
}

our %tokens;
our @tokens = qw(IF LAN IFLAN HOST PROTO PORT ICMPTYPE MACRO
		REDIRECT MASQU ACCEPT DROP REJECT MY YOUR IP
		GO CH TO BY ANY SERVICE USE CLIENT SERVER RETURN
		tcp udp icmp NAT IO FORWARD LOG LOGDROP RAW USER GROUP EVAL);
sub _Lexer {
    my($parser)=shift;

    unless (%tokens) {
        foreach (@tokens) {
            $tokens{$_} = uc($_);
        }
    }
    while (1) {
        unless (defined($parser->YYData->{INPUT}) && $parser->YYData->{INPUT}) {
            $parser->YYData->{INPUT} = <STDIN>;
            unless (defined($parser->YYData->{INPUT}) && $parser->YYData->{INPUT}) {
                dpr(7,"EOF\n");
                return('',undef) 
            }
            dpr(2,$parser->YYData->{INPUT});
            $parser->YYData->{INPUT}=~s/#.*$//;     #Komment
    	    $parser->YYData->{INPUT}=~s/\s+$//;     #sor végi space
        }
        last if (defined($parser->YYData->{INPUT}) && $parser->YYData->{INPUT});
    }

    $parser->YYData->{INPUT}=~s/^\s+//;
    MACRO: while (defined(%macros) || %macros) {
        my $macnm;
        foreach $macnm (keys(%macros)) {
            my $mac = $macros{$macnm};
            next MACRO if ($parser->YYData->{INPUT} =~ s/\$$macnm\s*\(\s*\)/$mac/);
            if ($parser->YYData->{INPUT} =~ m/\$$macnm\s*\(([^\)]+)\)/) {
                my @parm = split(/,/,$1);
	        dpr(2,"$macnm=$mac parm: @parm\t");
                my ($i, $m);
                for ($i = 0; $i < 10 && defined($parm[$i]);) {
		    my $t = $parm[$i];
		    ++$i;
		    dpr(2,"{$i:$t }");
                    $mac =~ s/\$$i/$t/g;
                }
		my $x = $parser->YYData->{INPUT};
		dpr(2,"($x)\t");
                $parser->YYData->{INPUT} =~ s/\$$macnm\s*\([^\)]+\)/$mac/;
		$x = $parser->YYData->{INPUT};
		dpr(2," => $mac ($x)\n");
                next MACRO;
            }
            next MACRO if ($parser->YYData->{INPUT} =~ s/\$$macnm/$mac/);
        }
        last MACRO;
    }

    for ($parser->YYData->{INPUT}) {
        s/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})// and do {
            dpr(1,"token: IP:$1\n");
            return ('IPA', $1);
        };
        s/^(\d+)// and do {
            dpr(1,"token: INT:$1\n");
            return('INT',$1);
        };
        ( s/^"([^"]*)"// or
          s/^'([^']*)'// ) and do {	#"/ { # ez a krixkrax csak a higlite miatt
            dpr(1,"token: NAME:$1\n");
            return('STRING',$1);
        };
        s/^(\w+)// and do {
            my $f = $1;
            if (defined($tokens{$f})) {
                dpr(1,"Token: $f ($tokens{$f})\n");
                return ($tokens{$f}, $f);
            }
            dpr(1,"token: NAME:$f\n");
            return('NAME',$f);
        };
        s/^(.)// and do {
	    dpr(2,"T.CHAR: $1\n");
            return($1,$1);
	};
    }
}

sub Run {
    my $r;
    my($self)=shift;
    while (@_) {
	my $k = shift;
	my $v = shift;
	$self->{$k} = $v;
    }
    $MySelf = $self;
    $deblev = $self->{Debug} if (defined($self->{Debug}));
    $r = $self->YYParse( yylex => \&_Lexer, yyerror => \&_Error );
    dpr(1, "**** NAT ****\n$nat\n");
    $self->{Nat}  = $nat;
    $self->{Chs}  = \%chs;
    $self->{Pol}  = \%pol;
    dpr(1, "**** FILT ****\n$filt\n");
    $self->{Filt} = $filt;
    $self->{Mods} = \@mods;
    $self->{Ifaces}  = \%ifaces;
    return $r;
}


1;

#!/usr/bin/perl
# -*- coding: utf-8 -*-

%{
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
%}

%start	all

%token  '(' ')' '{' '}' ';' '/' ',' '!' ':' '+' '-' '*'

%left  '+'  '-'
%left  '*'  '/'


%token  IF LAN IFLAN HOST PROTO PORT ICMPTYPE MACRO
%token	REDIRECT MASQU ACCEPT DROP REJECT MY YOUR IP
%token	GO CH TO BY ANY SERVICE USE CLIENT SERVER RETURN
%token	TCP UDP ICMP NAT IO FORWARD LOG LOGDROP RAW USER GROUP
%token  EVAL

%token  NAME STRING INT IPA

%%
all     :   defines
            NAT     ':' natdefs
            IO      iopol ':' iodefs
            FORWARD fwpol ':' fwdefs
        ;
defines :   define defines
        |
        ;
define  :   MACRO    NAME STRING ';'    { $macros{$_[2]} = $_[3]; }
        |   IF       NAME intf1 ';'     { $ifs{$_[2]}    = $_[3]; }
        |   LAN      NAME lan ';'       { $lans{$_[2]}   = $_[3]; }
        |   IFLAN    NAME intf1 lan ';' { $ifs{$_[2]."if"} = $_[3];
                                          $lans{$_[2]."lan"} = $_[4];
                                          $ips{$_[2]."ip"} = &ipmsk($_[4], $_[3]); }
        |   HOST     NAME ip ';'        { $ips{$_[2]}    = $_[3]; }
        |   IP       NAME ip ';'        { $ips{$_[2]}    = $_[3]; }
        |   PORT     NAME port ';'      { $ports{$_[2]}  = $_[3]; }
        |   PROTO    NAME proto ';'     { $protos{$_[2]} = $_[3]; }
        |   ICMPTYPE NAME INT ';'       { $icmpts{$_[2]} = $_[3]; }
        ;
intf1   :   NAME                        { defined($ifs{$_[1]})  ? $ifs{$_[1]} : &__error("Undefined interface: $_[1]"); }
        |   STRING                      { $_[1]; }
        ;
intf    :   intf1			{ $_[1]; }
	|   intf1 '/' intf1		{ $_[1] . '/' . $_[3]; }
	|   '/' intf1			{ '/' . $_[2]; }
	; 
lan     :   NAME                        { defined($lans{$_[1]}) ? $lans{$_[1]} : &__error("Undefined lan: $_[1]"); }
        |   ip '/' mask                 { "$_[1]/$_[3]"; }
        ;
ip      :   NAME                        { defined($ips{$_[1]})  ? $ips{$_[1]} : &__error("Undefined ip: $_[1]"); }
        |   IPA                         { $_[1]; }
	|   IP '(' int ',' int ',' int ',' int ')'
					{ $_[3] . '.' . $_[5] . '.' . $_[7] . '.' .$_[9]; }
	;
int	:   INT                         { $_[1]; }
	|   EVAL '(' expr ')'		{ $_[3]; }
        ;
expr	:   int				{ $_[1]; }
	|   expr '+' expr		{ $_[1] + $_[3]; }
        |   expr '-' expr               { $_[1] - $_[3]; }
        |   expr '*' expr               { $_[1] * $_[3]; }
        |   expr '/' expr               { $_[1] / $_[3]; }
        |   '(' expr ')'                { $_[2]; }
	;
mask    :   INT                         { $_[1]; }
        |   ip                          { $_[1]; }
        ;
port    :   pn ',' port                 { "$_[1],$_[3]"; }
        |   pn                          { $_[1]; }
        ;
pn      :   NAME                        { defined($ports{$_[1]}) ? $ports{$_[1]} :
					      &chkservice($_[1]) ? &chkservice($_[1]) :
						                   &__error("Undefined service: $_[1]"); }
        |   INT                         { $_[1]; }
        |   INT ':' INT                 { "$_[1]:$_[3]"; }
	    |   INT ':'			{ "$_[1]:"; }
        |   ':' INT                 	{ ":$_[2]"; }
        ;
prot    :   TCP                         { 'tcp'; }
        |   UDP                         { 'udp'; }
        ;
proto   :   prot                        { $_[1]; }
        |   ICMP                        { 'icmp'; }
        |   INT                         { $_[1]; }
        |   NAME                        { defined($protos{$_[1]})  ? $protos{$_[1]} : &__error("Undefined protocol: $_[1]"); }
        ;
iopol	:
	|   pol ',' pol			{ $pol{'INPUT'} = $_[1]; $pol{'OUTPUT'} = $_[3]; }
	;
fwpol	:
	|   pol				{ $pol{'FORWARD'} = $_[1];}
	;
pol	:   ACCEPT			{ 'ACCEPT'; }
	|   DROP			{ 'DROP'; }
	|   REJECT			{ 'REJECT'; }
	;
natdefs :   natdef natdefs
        |
        ;
natdef  :   define
        |   REDIRECT ipp TO ip parms ';'
                                        { &redirect($_[2], $_[4], '',    $_[5]); }
        |   REDIRECT ipp TO ip ':' port parms ';'
                                        { &redirect($_[2], $_[4], $_[6], $_[7]); }
        |   MASQU lan BY intf parms ';' { &masqu($_[2], $_[4], $_[5]); } 
	|   nraw
        ;
iodefs	:   iodef iodefs
	|
	;
iodef   :   act parms ';'               { &act('IO', $_[1], $_[2]); }
        |   GO NAME parms ';'           { &act('IO', $_[2], $_[3]); }
        |   CH NAME '{'                 { &ch($_[2]); }
                iodefs
            '}'                         { pop(@chst); }
        |   optnm parms '{'             { &act('IO', $_[1], $_[2]); &ch($_[1]); }
                iodefs
            '}'                         { pop(@chst); }
	|   fraw
        ;
fwdefs  :   fwdef fwdefs
	|
	;
fwdef   :   act parms ';'               { &act('FW', $_[1], $_[2]); }
        |   GO NAME parms ';'           { &act('FW', $_[2], $_[3]); }
        |   CH NAME '{'                 { &ch($_[2]); }
                fwdefs
            '}'                         { pop(@chst); }
        |   optnm parms '{'             { &act('FW', $_[1], $_[2]); &ch($_[1]); }
                fwdefs
            '}'                         { pop(@chst); }
	|   fraw
        ;
fraw	:   raw				{ $filt .= "$_[1]"; }
	;
nraw	:   raw				{ $nat .= "$_[1]"; }
	;
raw	:   RAW STRING ';'		{ raw($_[2]); }
	;
parms   :                               { \%null; }
        |   '(' prms ')'                { $_[2]; }
        ;
prms    :   parm prms                   { hashcat($_[1],$_[2]); }
        |                               { \%null; }
        ;
parm    :   IF ifp ';'                  { {'IF'       => $_[2] }; }
        |   IF ifp TO ifp ';'           { {'IFTO'     => "$_[2];$_[4]" }; }
        |   IP ipp ';'                  { {'IP'       => $_[2] }; }
        |   IP ipp TO ipp ';'           { {'IPTO'     => "$_[2];$_[4]" }; }
        |   YOUR IP ipp ';'             { {'YOURIP'   => $_[3] }; }
        |   MY IP ipp ';'               { {'MYIP'     => $_[3] }; }
        |   PORT port ';'               { {'PORT'     => $_[2] }; }
        |   PROTO protos ';'            { {'PROTO'    => $_[2] }; }
        |   PORT portp TO portp ';'     { {'PORTTO'   => "$_[2];$_[4]" }; }
        |   MY PORT portp ';'           { {'MYPORT'   => $_[3] }; }
        |   YOUR PORT portp ';'         { {'YOURPORT' => $_[3] }; }
        |   SERVER ipp ';'              { {'SERVER'   => $_[2] }; }
        |   CLIENT ipp ';'              { {'CLIENT'   => $_[2] }; }
        |   ICMPTYPE icmpt ';'          { {'ICMPT'    => $_[2] }; }
	|   USER NAME ';'		{ {'USER'     => $_[2] }; }
	|   GROUP NAME ';'		{ {'GROUP'    => $_[2] }; }
        ;
ifp     :   intf                        { $_[1]; }
        |   '!' intf                    { "! $_[2]"; }
        |   ANY                         { ''; }
        ;
ippp	:   NAME			{ defined($ips{$_[1]})  ? $ips{$_[1]} :
                                          defined($lans{$_[1]}) ? $lans{$_[1]} : &__error("Undefined lan or ip: $_[1]"); ; }
        |   ip '/' mask                 { "$_[1]/$_[3]"; }
        |   IP                          { $_[1]; }
	;
ipp     :   ippp                        { $_[1]; }
        |   '!' ippp                    { "! $_[2]"; }
        |   ANY                         { ''; }
        ;
icmpt   :   INT                         { $_[1]; }
        |   NAME                        { defined($icmpts{$_[1]})  ? $icmpts{$_[1]} : &__error("Undefined icmp type: $_[1]"); }
        ;
portp   :   port                        { $_[1]; }
        |   ANY                         { ''; }
        ;
protos  :   proto ',' protos            { "$_[1],$_[3]"; }
        |   proto                       { $_[1]; }
        ;
act     :   ACCEPT                      { 'ACCEPT';  }
        |   DROP                        { 'DROP';    }
        |   REJECT                      { 'REJECT';  }
        |   LOG                         { 'LOG';     }
        |   LOGDROP                     { 'logdrop'; }
        |   RETURN                      { 'RETURN';  }
        |   USE                         { 'USE';    }
        |   SERVICE                     { 'SERVICE'; }
        ;
optnm	:   NAME			{ $_[1]; }
	|				{ $cnt++, "an${cnt}x"; }
	;
%%

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


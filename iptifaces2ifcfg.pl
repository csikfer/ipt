#!/usr/bin/perl -w

my $src = "/var/log/ipt_ifaces.log";
die "Unable to open $src file, aborted." unless (open(SRC, "<$src"));

my $parent;

while (<SRC>) {
   my ($ifn, $addrmsk) = split(/\s+/);		# Interfész név, cím/maszk
   my ($ip, $msk)      = split(/\//, $addrmsk);	# cím, maszk
   if ($msk =~ /^\d+$/) {			# ha a maszk csak bitszám, átalakítjuk
       $msk = &n2dec(~((1 << (32 - $msk)) -1));
   }
   my $i;
   my $nip = &dec2n($ip);
   my $nmk = &dec2n($msk);
   my $net = &n2dec($nip &  $nmk);
   my $brk = &n2dec($nip | ~$nmk);


   die "Target file: ifcfg-$ifn open error, abort." unless (open(TRG, ">ifcfg-$ifn"));
   if ($ifn =~ /^vlan(\d+)$/) {
      my $id = $1;
      print TRG "
DEVICE=vlan$id
PARENTDEV=$parent
VID=$id
ONBOOT=yes
BOOTPROTO=none
IPADDR=$ip
NETMASK=$msk
USERCTL=no
NETWORK=$net
BROADCAST=$brk
PEERDNS=no
TYPE=Ismeretlen
IPV6INIT=no
";
   }
   elsif ($ifn =~ /^([^:])+:(\d+)$/) {
      my $nal = $2;
      print TRG "
TYPE=Ethernet
DEVICE=$ifn
IPADDR=$ip
BOOTPROTO=none
NETMASK=$msk
ONPARENT=yes
USERCTL=no
PEERDNS=no
IPV6INIT=no
";
   }
   else {
      $parent = $ifn;	# A vlan elötti (nem vlan) interfészt kinevezzük parent-nek
      print TRG "
TYPE=Ethernet
DEVICE=$ifn
BOOTPROTO=none
BROADCAST=$brk
IPADDR=$ip
NETMASK=$msk
NETWORK=$net
ONBOOT=yes
USERCTL=no
PEERDNS=no
IPV6INIT=no
";
   }
   close TRG;
}

sub n2dec()
{
   my ($n) = @_;
   my $r = $n % 256;
   $n /= 256;
   $r = ($n % 256) . "." . $r; 
   $n /= 256;
   $r = ($n % 256) . "." . $r; 
   $n /= 256;
   return ($n % 256) . "." . $r; 
}
sub dec2n()
{
   my ($ip) = @_;
   my $n = 0;
   foreach my $i (split(/\./, $ip)) {
      $n = $n * 256 + $i;
   }
   return $n;
}
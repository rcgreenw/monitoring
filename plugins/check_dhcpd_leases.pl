#! /usr/bin/perl -w
use strict;
use Data::Dump qw[ pp ];
use Getopt::Long;

# Nagios specific

#use lib "/usr/lib64/nagios/plugins";
# Constants OK, WARNING, CRITICAL, and UNKNOWN exported by default
use Nagios::Plugin;
use Nagios::Plugin::Threshold;

# Option variable defaults
my $o_subnet         = undef;   # Subnets to report on
my $o_warn           = undef;       # Warn
my $o_crit           = undef;       # Crit
my $o_help           = undef;   # wan't some help ?
my $o_verbose        = undef;   # verbose mode
my $o_debug          = undef;   # debug mode
my $o_version        = undef;   # print version
my $o_noreg          = undef;   # Do not use Regexp for name
my $o_timeout        = undef;   # Default defined above
my $o_maxmsgsize     = undef;   # See Net-SNMP
my $o_maxrepetitions = undef;   # See Net-SNMP
my $o_showall        = undef;   # Show all subnets even if OK
my $o_leasefile      = "/var/lib/dhcpd/dhcpd.leases";   # DHCPD lease file

# Internal variables
my $subnet_hash      = {};      # Subnet hash
my @subnet_list      = ();      # Subnet list
my @warn_list        = ();      # Warning list
my @crit_list        = ();      # Critical list
my $output           = "";
my $output_unkn      = "";
my $output_crit      = "";
my $output_warn      = "";
my $output_ok        = "";
my $exit_error       = 0;

sub parseLeases {
   my( $source, $depth, %leases ) = @_;
   $depth++;
   while (my $line = shift(@$source)) {
      chomp($line);
      $line =~ m/(.*)([\{\};])/;
      my $data = $1;
      if (!defined($2)) {
      } elsif ($2 =~ m/}/) {
         return \%leases;
      } elsif ($2 =~ m/{/) {
         if ($data =~ m/failover peer "(.*)" state/) {
            $data = $1;
            $leases{'failover'}{$data} = parseLeases( $source, $depth );
         } elsif ($data =~ m/lease (.*) /) {
            $data = $1;
            my $lease = parseLeases( $source, $depth );
            $leases{'leases'}{$data} = $lease;
         }
      } elsif ($2 =~ m/;/) {
         if ($data =~ m/(my|partner) state (.*) at (.*)/) {
            $leases{"$1state"} = $2;
            $leases{"$1timestamp"} = $3;
         } elsif ($data =~ m/\s+([a-z -]+) \"?([^\"]*)\"?/) {
            $leases{$1} = $2;
         }
      } else {
      }
   }
   return \%leases;
}

sub max ($$) { $_[$_[0] < $_[1]] }
sub min ($$) { $_[$_[0] > $_[1]] }

#From: http://www.mikealeonetti.com/wiki/index.php?title=Check_if_an_IP_is_in_a_subnet_in_Perl
use Socket qw( inet_aton );

sub ip2long($);
sub in_subnet($$);

sub ip2long($)
{
   return( unpack( 'N', inet_aton(shift) ) );
}

sub in_subnet($$)
{
   my $ip = shift;
   my $subnet = shift;

   my $ip_long = ip2long( $ip );

   if( $subnet=~m|(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$| )
   {
      my $subnet = ip2long( $1 );
      my $mask = ip2long( $2 );

      if( ($ip_long & $mask)==$subnet )
      {
         return( 1 );
      }
   }
   elsif( $subnet=~m|(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$| )
   {
      my $subnet = ip2long( $1 );
      my $bits = $2;
      my $mask = -1<<(32-$bits);

      $subnet&= $mask;

      if( ($ip_long & $mask)==$subnet )
      {
         return( 1 );
      }
   }
   elsif( $subnet=~m|(^\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$| )
   {
      my $start_ip = ip2long( $1.$2 );
      my $end_ip = ip2long( $1.$3 );

      if( $start_ip<=$ip_long and $end_ip>=$ip_long )
      {
         return( 1 );
      }
   }
   elsif( $subnet=~m|^[\d\*]{1,3}\.[\d\*]{1,3}\.[\d\*]{1,3}\.[\d\*]{1,3}$| )
   {
      my $search_string = $subnet;

      $search_string=~s/\./\\\./g;
      $search_string=~s/\*/\.\*/g;

      if( $ip=~/^$search_string$/ )
      {
         return( 1 );
      }
   }

   return( 0 );
}

sub usage {
    return "Usage: $0 [-v] -l <lease_file> "
         ."-s <subnet>[,<subnet>] [-S] [-t <timeout>] [-V]\n";
}

sub help {
   my $help = usage();
   $help .= <<EOT;
-v, --verbose
   print leases found
-d, --debug
   print extra debugging information
-h, --help
   print this help message
-l, --leasefile=<lease_file>
   Lease file, $o_leasefile
-s, --subnet=<subnet>[,<subnet>...]
   Comma separated subnets to report on.
   By default, report on all subnets.
-S, --showall
   Show all services in the output, instead of only the non-active ones.
-t, --timeout=INTEGER
   timeout for SNMP in seconds (Default: 5)
EOT
   return $help;
}


my $np = Nagios::Plugin->new(shortname => "DHCPD Leases");
Getopt::Long::Configure ("bundling_override");
GetOptions(
      'v'     => \$o_verbose,   'verbose'     => \$o_verbose,
      'd'     => \$o_debug,     'debug'       => \$o_debug,
      'h'     => \$o_help,      'help'        => \$o_help,
      't:i'   => \$o_timeout,   'timeout:i'   => \$o_timeout,
      'w:s'   => \$o_warn,      'warn'        => \$o_warn,
      'c:s'   => \$o_crit,      'crit'        => \$o_crit,
      's:s'   => \$o_subnet,    'subnet:s'    => \$o_subnet,
      'l:s'   => \$o_leasefile, 'leasefile:s' => \$o_leasefile,
      'S'     => \$o_showall,   'showall'     => \$o_showall,  
      'V'     => \$o_version,   'version'     => \$o_version
   );
if (defined($o_help)) { help(); $np->nagios_exit(UNKNOWN, help()); }

if (defined($o_subnet)) { 
   @subnet_list = split(/,/,$o_subnet); 
} else {
   @subnet_list = ('0.0.0.0/0');
}

if (defined($o_warn)) {
   @warn_list = split(/,/,$o_warn);
   if (scalar(@warn_list) == scalar(@subnet_list)) { 
      # Lists are same length, 1:1 mapping
   } elsif (scalar(@warn_list) == 1) { 
      # Fill list with single value
      @warn_list = ($o_warn) x scalar(@subnet_list);
   } else {
      $output_unkn = "Number of warning levels must match number of subnets.\n";
      $np->nagios_exit(UNKNOWN, $output_unkn); 
   }
}

if (defined($o_crit)) {
   @crit_list = split(/,/,$o_crit);
   if (scalar(@crit_list) == scalar(@subnet_list)) { 
      # Lists are same length, 1:1 mapping
   } elsif (scalar(@crit_list) == 1) { 
      # Fill list with single value
      @crit_list = ($o_crit) x scalar(@subnet_list);
   } else {
      $output_unkn = "Number of critical levels must match number of subnets.\n";
      $np->nagios_exit(UNKNOWN, $output_unkn); 
   }
}

pp @subnet_list if ($o_debug);
pp @warn_list if ($o_debug);
pp @crit_list if ($o_debug);
foreach my $subnet (@subnet_list) { 
   my $l_warn = shift(@warn_list);
   my $l_crit = shift(@crit_list);
   $subnet_hash->{$subnet} = {'warn' => $l_warn, 'crit' => $l_crit};
} 

eval { open FILE, $o_leasefile or die $!; };
if ($@) {
   $output_crit = "DHCP Leases CRITICAL - Error opening lease file ($o_leasefile): ".$!;
   $np->nagios_exit(CRITICAL, $output_crit); 
}



my @file = <FILE>;

my $leases = parseLeases( \@file );
pp $leases if ($o_debug);

foreach my $l_lease (keys %{ $leases->{'leases'} }) {
   my $l_state = $leases->{'leases'}->{$l_lease}->{'binding state'};
   print "$l_lease->$l_state\n" if ($o_verbose);
   if (defined($o_subnet)) {
      foreach my $l_subnet (keys %{ $subnet_hash }) {
         if (in_subnet($l_lease, $l_subnet)) { 
            $subnet_hash->{$l_subnet}{$l_state}++; 
            print("State: $l_state Count: ".$subnet_hash->{$l_subnet}{$l_state}."\n") if ($o_verbose);
         }
      }
   } else {
      $subnet_hash->{'0.0.0.0/0'}{$l_state}++;
      print("State: $l_state Count: ".$subnet_hash->{'0.0.0.0/0'}{$l_state}."\n") if ($o_verbose);
   }
}

pp $subnet_hash if ($o_debug);

foreach my $l_subnet (@subnet_list) {
   my $l_warn = defined($subnet_hash->{$l_subnet}{'warn'})?$subnet_hash->{$l_subnet}{'warn'}:"0:";
   my $l_crit = defined($subnet_hash->{$l_subnet}{'crit'})?$subnet_hash->{$l_subnet}{'crit'}:"0:";
   my $l_free = defined($subnet_hash->{$l_subnet}{'free'})?$subnet_hash->{$l_subnet}{'free'}:"0:";
   my $l_active = defined($subnet_hash->{$l_subnet}{'active'})?$subnet_hash->{$l_subnet}{'active'}:0;
   my $l_backup = defined($subnet_hash->{$l_subnet}{'backup'})?$subnet_hash->{$l_subnet}{'backup'}:0;
   my $l_threshold = Nagios::Plugin::Threshold->set_thresholds( warning  => $l_warn, critical => $l_crit,);
   my $l_error = $l_threshold->get_status($l_free);
   $exit_error = max($exit_error,$l_error);
   if ($l_error == CRITICAL) {
      $output_crit .= "$l_subnet (FREE:$l_free CRIT:".$l_threshold->critical." active:$l_active backup:$l_backup) ";
      $exit_error = max($exit_error,CRITICAL);
   } elsif ($l_error == WARNING) {
      $output_warn .= "$l_subnet (FREE:$l_free WARN:".$l_threshold->warning." active:$l_active backup:$l_backup) ";
      $exit_error = max($exit_error,WARNING);
   } else {
      $output_ok .= "$l_subnet (free:$l_free active:$l_active backup:$l_backup) ";
   }
}

$output = "$output_unkn$output_crit$output_warn$output_ok";
$np->nagios_exit($exit_error, $output); 


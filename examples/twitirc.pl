#!/usr/bin/perl
use warnings;
use strict;
use Log::Log4perl qw/:easy/;
use Getopt::Long;
use POE qw(Component::TSTP);
use YAML;

Log::Log4perl->easy_init($DEBUG);

GetOptions('-c=s' => \my $conf);
$conf or die "Usage: twitirc.pl -c=twitirc.yml\n";

use Net::Twitter::IRC;

Net::Twitter::IRC->new(%{ YAML::LoadFile($conf) });

POE::Kernel->run;

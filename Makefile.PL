use inc::Module::Install 0.67;
use strict;
use warnings;

use 5.008001;

name     'Net-Twitter-IRC';
perl_version '5.008001';
all_from 'lib/Net/Twitter/IRC.pm';

requires 'MooseX::POE'                 => 0;
requires 'Net::Twitter'                => 0;
requires 'Email::Valid'                => 0;
requires 'POE::Component::Server::IRC' => 0.02005;

eval {
    system 'pod2text lib/Net/Twitter/IRC.pm > README';
};

auto_install;
WriteAll;

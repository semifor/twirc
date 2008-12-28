use inc::Module::Install 0.67;
use strict;
use warnings;

use 5.008001;

name     'Net-Twitter-IRC';
perl_version '5.008001';
all_from 'lib/Net/Twitter/IRC.pm';

install_script  'bin/twirc';

requires 'MooseX::POE'                 => 0;
requires 'Net::Twitter'                => '1.22';
requires 'Email::Valid'                => 0;
requires 'POE::Component::Server::IRC' => 0.02005;
requires 'Log::Log4perl';
requires 'POE::Component::TSTP';
requires 'LWP::UserAgent::POE'         => '0.02';
requires 'HTML::Entities';
requires 'Text::Truncate';

eval {
    system 'pod2text lib/Net/Twitter/IRC.pm > README';
};

auto_install;
WriteAll;

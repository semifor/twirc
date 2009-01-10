use inc::Module::Install 0.67;
use strict;
use warnings;

use 5.008001;

name     'POE-Component-Server-Twirc';
perl_version '5.008001';
all_from 'lib/POE/Component/Server/Twirc.pm';

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
requires 'MooseX::SimpleConfig';
requires 'MooseX::Getopt'              => '0.15';
requires 'MooseX::Log::Log4perl::Easy';
requires 'Proc::Daemon';
requires 'FindBin';
requires 'MooseX::Storable';

eval {
    system 'pod2text lib/POE/Component/Server/Twirc.pm > README';
};

auto_install;
WriteAll;

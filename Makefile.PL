use inc::Module::Install;
use strict;
use warnings;

name     'POE-Component-Server-Twirc';
perl_version '5.008001';
all_from 'lib/POE/Component/Server/Twirc.pm';

install_script  'bin/twirc';

requires 'MooseX::POE'                 => 0.205;
requires 'Net::Twitter'                => '3.07000';
requires 'Email::Valid'                => 0;
requires 'POE::Component::Server::IRC' => 0.02005;
requires 'Log::Log4perl';
requires 'POE::Component::SSLify';
requires 'POE::Component::TSTP';
requires 'LWP::UserAgent::POE'         => '0.02';
requires 'String::Truncate';
requires 'MooseX::SimpleConfig';
requires 'MooseX::Getopt'              => '0.15';
requires 'MooseX::Log::Log4perl::Easy';
requires 'Proc::Daemon';
requires 'FindBin';
requires 'MooseX::Storage';
requires 'Path::Class::File';

if ( $Module::Install::Author ) {
    system 'pod2text lib/App/Twirc/Manual.pod > README';
}

auto_set_repository;
auto_manifest;
auto_install;

WriteAll;

use inc::Module::Install;
use strict;
use warnings;

name     'POE-Component-Server-Twirc';
perl_version '5.008001';
all_from 'lib/POE/Component/Server/Twirc.pm';

install_script  'bin/twirc';

requires 'AnyEvent::Twitter::Stream';
requires 'Config::Any';
requires 'Email::Valid'                => 0;
requires 'Encode';
requires 'FindBin';
requires 'HTML::Entities';
requires 'Log::Log4perl';
requires 'LWP::UserAgent::POE'         => '0.02';
requires 'Moose';
requires 'MooseX::Getopt'              => '0.15';
requires 'MooseX::Log::Log4perl::Easy';
requires 'MooseX::POE'                 => 0.205;
requires 'MooseX::SimpleConfig';
requires 'MooseX::Storage';
requires 'Net::Twitter'                => '3.11007'; # xauth
requires 'Path::Class::File';
requires 'POE::Component::Server::IRC' => 0.02005;
requires 'POE::Component::TSTP';
requires 'Proc::Daemon';
requires 'Regexp::Common::URI';
requires 'Scalar::Util';
requires 'String::Truncate';
requires 'Try::Tiny';

if ( $Module::Install::Author ) {
    system 'pod2text lib/App/Twirc/Manual.pod > README';
}

auto_set_repository;
auto_manifest;
auto_install;

WriteAll;

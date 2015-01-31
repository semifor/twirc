use inc::Module::Install;
use strict;
use warnings;

name     'POE-Component-Server-Twirc';
perl_version '5.008001';
all_from 'lib/POE/Component/Server/Twirc.pm';

install_script  'bin/twirc';

# Needed to run this script
configure_requires 'Module::Install::Repository';
configure_requires 'Module::Install::AutoManifest';
configure_requires 'Module::Install::Contributors';

requires 'AnyEvent::Twitter::Stream'   => '0.23'; # APIv1.1
requires 'Config::Any';
requires 'Encode';
requires 'FindBin';
requires 'HTML::Entities';
requires 'JSON::Any';
requires 'JSON::MaybeXS';
requires 'Log::Log4perl';
requires 'LWP::UserAgent::POE'         => '0.02';
requires 'Moose';
requires 'MooseX::Getopt'              => '0.15';
requires 'MooseX::Log::Log4perl::Easy';
requires 'MooseX::POE'                 => 0.215;
requires 'MooseX::SimpleConfig';
requires 'MooseX::Storage';
requires 'Net::Twitter'                => '4.00006'; # xauth + APIv1.1
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

contributors 'Adam Prime <adam.prime@utoronto.ca>';
contributors 'Peter Roberts <me+dev@peter-r.co.uk>';

auto_set_repository;
homepage   'https://github.com/semifor/twirc';
bugtracker 'https://github.com/semifor/twirc/issues';

auto_manifest;
auto_install;

WriteAll;

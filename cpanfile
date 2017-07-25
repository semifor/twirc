on 'runtime' => sub {
    requires 'base';
    requires 'strict';
    requires 'warnings';
    requires 'utf8';

    requires 'AnyEvent'                    => 0;
    requires 'AnyEvent::Twitter'           => 0;
    requires 'AnyEvent::Twitter::Stream'   => 0.23;
    requires 'Config::Any'                 => 0;
    requires 'Encode'                      => 0;
    requires 'FindBin'                     => 0;
    requires 'HTML::Entities'              => 0;
    requires 'JSON::MaybeXS'               => 0;
    requires 'Log::Log4perl'               => 0;
    requires 'Moose'                       => 0;
    requires 'MooseX::Getopt'              => 0.15;
    requires 'MooseX::Log::Log4perl::Easy' => 0;
    requires 'MooseX::POE'                 => 0.215;
    requires 'MooseX::SimpleConfig'        => 0;
    requires 'MooseX::Storage'             => 0;
    requires 'Net::Twitter'                => 0;
    requires 'POE::Component::Server::IRC' => 0.02005;
    requires 'POE::Component::TSTP'        => 0;
    requires 'POE::Loop::AnyEvent'         => 0;
    requires 'Path::Class::File'           => 0;
    requires 'Proc::Daemon'                => 0;
    requires 'Regexp::Common::URI'         => 0;
    requires 'Scalar::Util'                => 0;
    requires 'String::Truncate'            => 0;
    requires 'Try::Tiny'                   => 0;
};

on 'build' => sub {
    requires 'strict';
    requires 'warnings';
    requires 'ExtUtils::MakeMaker';
};

on 'test' => sub {
    requires 'strict';
    requires 'warnings';
    requires 'Test::More';
};

on develop => sub {
    requires 'Archive::Tar::Wrapper' => 0.15;
    requires 'Dist::Zilla';
    requires 'Dist::Zilla::Plugin::Prereqs::FromCPANfile';
    requires 'Dist::Zilla::PluginBundle::Starter';
    requires 'Pod::Coverage::TrustPod';
    requires 'Test::Pod';
    requires 'Test::Pod::Coverage';
};

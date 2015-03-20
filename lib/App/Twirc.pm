package App::Twirc;

use Moose;
use Config::Any;
use POE::Component::Server::Twirc;
use Proc::Daemon;
use Path::Class::File;
use Log::Log4perl qw/:easy/;

with 'MooseX::Getopt',
     'MooseX::Log::Log4perl::Easy';

has configfile => (
    metaclass   => 'Getopt',
    cmd_aliases => 'c',
    isa         => 'Str',
    is          => 'ro',
    documentation => 'configration file name',
);

has background => (
    metaclass   => 'Getopt',
    cmd_aliases => 'b',
    isa         => 'Bool',
    is          => 'ro',
    documentation => 'run as daemon',
);

has authenticate => (
    metaclass   => 'Getopt',
    cmd_aliases => [qw/a auth/],
    isa         => 'Bool',
    is          => 'ro',
    default     => 0,
    documentation => 'force Twitter authentication',
);

has state_file => (
    metaclass   => 'Getopt',
    cmd_aliases => 's',
    isa         => 'Str',
    is          => 'ro',
    predicate   => 'has_state_file',
    documentation => 'state file name',
);

has debug => (
    metaclass   => 'Getopt',
    cmd_aliases => 'd',
    isa         => 'Bool',
    is          => 'ro',
    default     => 0,
    documentation => 'set logging level to DEBUG',
);

sub run {
    my $self = shift;

    my $config;
    if ( my $file = $self->configfile ) {
        $config = Config::Any->load_files({ files => [ $file ], use_ext => 1 });
        $config = $config->[0]{$file};
    }

    # override/provide config options from the commandline
    $$config{state_file} = $self->state_file if $self->has_state_file;
    $$config{log_level}  = 'DEBUG'           if $self->debug;

    Log::Log4perl->easy_init({
        layout => '%d{HH:mm:ss} [%p] %m%n',
        level  => $$config{log_level} && eval "\$$$config{log_level}" || $WARN,
    });

    # Make sure state_file is absolute before we background (which does a cd /).
    $$config{state_file} = Path::Class::File->new($config->{state_file})->absolute->stringify
        if $$config{state_file};

    my $state = $$config{state_file} && -r $$config{state_file}
              ? POE::Component::Server::Twirc::State->load($$config{state_file})
              : POE::Component::Server::Twirc::State->new;

    if ( $self->authenticate || !$state->access_token ) {
        # bloody hack until Twitter restores xauth

        my $nt = Net::Twitter->new(
            traits => [qw/OAuth/],
            POE::Component::Server::Twirc->_twitter_auth,
            ssl => 1,
        );
        print "Authorize twirc at ", $nt->get_authorization_url, "\nThen, enter the PIN# provided: ";

        my $pin = <STDIN>;
        chomp $pin;

        my ( $token, $secret ) = $nt->request_access_token(verifier => $pin);
        $state->access_token($token);
        $state->access_token_secret($secret);

        $state->store($$config{state_file}) if $$config{state_file};
    }

    if ( $self->background ) {
        Proc::Daemon::Init;
        POE::Kernel->has_forked;
    }
    else {
        eval 'use POE qw(Component::TSTP)';
        die "$@\n" if $@;
    }

    $config->{plugins} = $self->_init_plugins($config);
    POE::Component::Server::Twirc->new(%{$config || {}}, state => $state);
    POE::Kernel->run;
}

sub _init_plugins {
    my ($self, $config) = @_;

    my $plugins = delete $config->{plugins};

    my @plugins;
    for my $plugin ( @$plugins ) {
        my ($class, $options) = ref $plugin ? %$plugin : ($plugin, {});
        $class = "App::Twirc::Plugin::$class" unless $class =~ s/^\+//;

        eval "use $class";
        die $@ if $@;

        push @plugins, $class->new($options);
    }
    return \@plugins;
}

no Moose;

__PACKAGE__->meta->make_immutable;

1;

__END__

=head1 NAME

App::Twirc - IRC is my twitter client

=head1 SYNOPSIS

    use App::Twirc;

    my $app = App::Twirc->new_with_options();
    $app->run;

=head1 DESCRIPTION

C<App::Twirc> is an IRC server making the IRC client of your choice your twitter client.  The C<twirc>
program in this distribution launches the application.

See L<App::Twirc::Manual> for more details.

=head1 OPTIONS

=over 4

=item configfile

Required.  The name of the configuration file containing options for L<POE::Component::Server::Twirc>.

=item background

Boolean value to determine whether to run in the foreground (0), or background (1).

=item authenticate

Forces OAuth authentication with Twitter, supplying a URL for Twitter OAuth
authentication and prompting for the OAuth verifier PIN. Use this method
re-authenticate with Twitter, if necessary.

=item state_file

Specifies a file name for loading/storing state information, including a list
of friends, followers_ids, and OAuth access tokens.

=item debug

Boolean, when set to 1, enables DEBUG level logging.

=back

=head1 METHODS

=over 4

=item run

Run the application.

=back

=head1 AUTHOR

Marc Mims <marc@questright.com>

=head1 LICENSE

Copyright (c) 2008 Marc Mims

You may distribute this code and/or modify it under the same terms as Perl itself.

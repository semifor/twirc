package App::Twirc;
use Moose;
use Config::Any;
use POE::Component::Server::Twirc;
use Proc::Daemon;
use Path::Class::File;

with 'MooseX::Getopt',
     'MooseX::Log::Log4perl::Easy';

has configfile => (
    metaclass   => 'Getopt',
    cmd_aliases => 'c',
    isa         => 'Str',
    is          => 'ro',
    required    => 1,
);

has background => (
    metaclass   => 'Getopt',
    cmd_aliases => 'b',
    isa         => 'Bool',
    is          => 'ro',
);

sub run {
    my $self = shift;

    my $file = $self->configfile;
    die "a configuration (option --configifle) is required\n" unless $file;

    my $config = Config::Any->load_files({ files => [ $file ], use_ext => 1 });
    $config = $config->[0]{$file};

    Log::Log4perl->easy_init({ layout => '%d{HH:mm:ss} [%p] %m%n' });

    # Hack! Make sure state_file is absolute before we background (which does a cd /).
    $config->{state_file} = Path::Class::File->new($config->{state_file})->absolute->stringify
        if $config->{state_file};

    if ( $self->background ) {
        Proc::Daemon::Init;
    }
    else {
        eval 'use POE qw(Component::TSTP)';
        die "$@\n" if $@;
    }

    my $poco = POE::Component::Server::Twirc->new($config);
    POE::Kernel->run;
}

1;

__END__

=head1 NAME

App::Twirc - IRC is my twitter client

=head1 SYNOPSIS

    use App::Twirc;

    my $twirc = App::Twirc->new_with_options();
    $twirc->run;

=head1 DESCRIPTION

C<App::Twirc> is an IRC server making the IRC client of your choice your twitter client.  The C<twitirc>
program in this distribution launches the application.

=head1 OPTIONS

=over 4

=item configfile

Required.  The name of the configuration file containing options for L<POE::Component::Server::Twirc>.

=item background

Boolean value to determine whether to run in the foreground (0), or background (1).

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

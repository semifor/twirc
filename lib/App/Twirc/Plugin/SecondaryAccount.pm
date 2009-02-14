package App::Twirc::Plugin::SecondaryAccount;
use Moose;
use Net::Twitter;
use POE::Component::Server::Twirc;

has net_twitter_options => ( isa => 'HashRef', is => 'ro', default => sub { {} } );
has username => ( isa => 'Str', is => 'ro', required => 1 );
has password => ( isa => 'Str', is => 'ro', required => 1 );
has option   => ( isa => 'Str', is => 'ro' );
has _twitter => ( isa => 'Net::Twitter', is => 'rw' );
has _option_regex => ( isa => 'Maybe[RegexpRef]', is => 'rw', default => undef );
has _useragent_class => ( isa => 'Str', is => 'ro', default => 'LWP::UserAgent::POE' );

sub BUILD {
    my $self = shift;

    $self->_twitter(Net::Twitter->new(
        username  => $self->username,
        password  => $self->password,
        source    => 'twircgw',
        useragent => 'twirc/' . POE::Component::Server::Twirc->VERSION,
        useragent_class => $self->_useragent_class,
        %{$self->net_twitter_options},
    ));

    if ( $self->option ) {
        my $option = quotemeta $self->option;
        $self->_option_regex(qr/^-$option(only)?\s+/);
    }
}

sub cmd_post {
    my ($self, $server, $channel, $nick, $textref) = @_;

    my $only;
    if ( my $option_regex = $self->_option_regex ) {
        $$textref =~ s/$option_regex// || return;
        $only = $1;
    }

    $self->_twitter->update($$textref);
    return $only; # return a true value to stop the processing chain
}

no Moose;

__PACKAGE__->meta->make_immutable;

1;

package POE::Component::Server::Twirc::State;

use Moose;
use MooseX::Storage;

with Storage(format => 'JSON', io => 'File');

has access_token         => isa => 'Str', is => 'rw';
has access_token_secret  => isa => 'Str', is => 'rw';

has twitter_users => (
    isa => 'HashRef',
    default => sub { {} },
    traits => [qw/Hash/],
    handles => {
        set_user_by_id    => 'set',
        get_user_by_id    => 'get',
        delete_user_by_id => 'delete',
        get_users         => 'values',
    },
);

has followers => (
    isa     => 'HashRef',
    traits  => [ qw/Hash/ ],
    is      => 'rw',
    default => sub { {} },
    handles => {
        add_follower_id    => 'set',
        remove_follower_id => 'delete',
        is_follower_id     => 'exists',
    },
);

around add_follower_id => sub {
    my ( $orig, $self, $id ) = @_;

    $self->$orig($id, undef);
};

has followers_updated_at => is => 'rw', isa => 'Int', default => 0;

no Moose;

__PACKAGE__->meta->make_immutable;

1;

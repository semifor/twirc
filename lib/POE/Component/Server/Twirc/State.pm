package POE::Component::Server::Twirc::State;
use Moose;
use MooseX::Storage;

with Storage(format => 'JSON', io => 'File');

has friends_timeline_id => ( isa => 'Str', is => 'rw' );
has user_timeline_id    => ( isa => 'Str', is => 'rw' );
has reply_id            => ( isa => 'Str', is => 'rw' );
has direct_message_id   => ( isa => 'Str', is => 'rw' );
has access_token        => ( isa => 'Str', is => 'rw' );
has access_token_secret => ( isa => 'Str', is => 'rw' );

no Moose;

__PACKAGE__->meta->make_immutable;

1;

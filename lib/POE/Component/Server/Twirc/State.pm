package POE::Component::Server::Twirc::State;
use Moose;
use MooseX::Storage;

with Storage(format => 'JSON', io => 'File');

has friends_timeline_id => ( isa => 'Int', is => 'rw' );
has user_timeline_id    => ( isa => 'Int', is => 'rw' );
has reply_id            => ( isa => 'Int', is => 'rw' );
has direct_message_id   => ( isa => 'Int', is => 'rw' );

1;

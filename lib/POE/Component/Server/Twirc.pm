package POE::Component::Server::Twirc;
use MooseX::POE;

use MooseX::AttributeHelpers;
use LWP::UserAgent::POE;
use POE qw(Component::Server::IRC);
use Net::Twitter;
use Email::Valid;
use Text::Truncate;
use POE::Component::Server::Twirc::LogAppender;
use POE::Component::Server::Twirc::State;

with 'MooseX::Log::Log4perl';

# Net::Twitter returns text with encoded HTML entities.  I *think* decoding
# properly belongs in Net::Twitter.  So, if it gets added, there:
# TODO: remove HTML::Entities and decode_entities calls.
use HTML::Entities;

our $VERSION = '0.07';

=head1 NAME

POE::Component::Server::Twirc - Twitter/IRC gateway

=head1 SYNOPSIS

    use POE::Component::Server::Twirc;

    POE::Component::Server::Twirc->new(
        irc_nickname        => $my_irc_nickname,
        twitter_username    => $my_twitter_username,
        twitter_password    => $my_twitter_password,
        twitter_screen_name => $my_twitter_screen_name,
    );

    POE::Kernel->run;

=head1 DESCRIPTION

C<POE::Component::Server::Twirc> provides an IRC/Twitter gateway.  Twitter friends are
added to a channel and messages they post on twitter appear as channel
messages in IRC.  The IRC interface supports several Twitter features,
including posting status updates, following and un-following Twitter feeds,
enabling and disabling device notifications, sending direct messages, and
querying information about specific Twitter users.

Friends who are also followers are given "voice" as a visual clue in IRC.

=head1 METHODS

=head2 new

Spawns a POE component encapsulating the Twitter/IRC gateway.

Arguments:

=over 4

=item irc_nickname

(Required) The irc nickname used by the owning user.

=cut

has irc_nickname        => ( isa => 'Str', is => 'ro', required => 1 );

=item twitter_username

(Required) The username (email address) used to authenticate with Twitter.

=cut

has twitter_username    => ( isa => 'Str', is => 'ro', required => 1 );

=item twitter_password

(Required) The password used to authenticate with Twitter.

=cut

has twitter_password    => ( isa => 'Str', is => 'ro', required => 1 );

=item twitter_screen_name

(Required) The user's Twitter screen name.

=cut

has twitter_screen_name => ( isa => 'Str', is => 'ro', required => 1 );


=item irc_server_name

(Optional) The name of the IRC server. Defaults to C<twitter.irc>.

=cut

has irc_server_name     => ( isa => 'Str', is => 'ro', default => 'twitter.irc' );

=item irc_server_port

(Optional) The port number the IRC server binds to. Defaults to 6667.

=cut

has irc_server_port     => ( isa => 'Int', is => 'ro', default => 6667 );

=item irc_server_bindaddr

(Optional) The local address to bind to. Defaults to all interfaces.

=cut

# will be defaulted to INADDR_ANY by POE::Wheel::SocketFactory
has irc_server_bindaddr => ( isa => 'Str', is => 'ro', default => undef );

=item irc_mask

(Optional) The IRC user/host mask used to restrict connecting users.  Defaults to C<*@127.0.0.1>.

=cut

has irc_mask            => ( isa => 'Str', is => 'ro', default => '*@127.0.0.1' );


=item irc_password

(Optional) Password used to authenticate to the IRC server.

=cut

has irc_password        => ( isa => 'Str', is => 'ro' );


=item irc_botname

(Optional) The name of the channel operator bot.  Defaults to C<tweeter>.  Select a name
that does not conflict with friends, followers, or your own IRC nick.

=cut

has irc_botname         => ( isa => 'Str', is => 'ro', default => 'tweeter' );


=item irc_botircname

(Optional) Text to be used as the channel operator bot's IRC full name.

=cut

has irc_botircname      => ( isa => 'Str', is => 'ro', default => 'Your friendly Twitter Agent' );


=item irc_channel

(Optional) The name of the channel to use.  Defaults to C<&twitter>.

=cut

has irc_channel         => ( isa => 'Str', is => 'ro', default => '&twitter' );


=item twitter_retry

(Optional) The number of seconds between polls for new status updates.  Defaults to 300
(5 minutes).  Twitter imposes a rate limit of 100 API calls per hour.  By default,
after initial start up, twirc makes a single API call every C<twitter_retry>
seconds.  Adding L</"check_replies"> and L</"check_direct_messages"> each
add an additional API call.  Setting C<twitter_retry> too low can cause twirc
to exceed the rate limit and delay receipt of messages.

Use the L</"rate_limit_status"> command to check your available API calls.

=cut

has twitter_retry       => ( isa => 'Int', is => 'ro', default => 300 );


=item twitter_retry_on_error

(Optional) The number of seconds to wait before retrying a failed poll for friends,
followers, or status updates.  Defaults to 60 (1 minute).

=cut

has twitter_retry_on_error => ( isa => 'Int', is => 'ro', default => 60 );


=item twitter_alias

(Optional) An alias to use for displaying incoming status updates from the owning user.
This is necessary if the user's IRC nickname and Twitter screen name are the
same.  Defaults to C<me>.

=cut

has twitter_alias       => ( isa => 'Str', is => 'ro', default => 'me' );

=item twitter_args

(Optional) A hashref of extra arguments to pass to C<< Net::Twitter->new >>.

=cut

has twitter_args => ( isa => 'HashRef', is => 'ro', default => sub { {} } );

=item echo_posts

(Optional) If false, posts sent by L<POE::Component::Server::Twirc> will not be redisplayed when received
is the friends_timeline.  Defaults to false.

Set C<echo_posts(1)> to see your own tweets in chronological order with the others.

=cut

has echo_posts => ( isa => 'Bool', is => 'rw', default => 0 );

=item favorites_count

(Optional) How many favorites candidates to display for selection. Defaults to 3.

=cut

has favorites_count => ( isa => 'Int', is => 'ro', default => 3 );

=item truncate_to

(Optional) When displaying tweets for selection, they will be truncated to this length.
Defaults to 60.

=cut

has truncate_to         => ( isa => 'Int', is => 'ro', default => 60 );

=item check_replies

(Optional) If true, checks for @replies when polling for friends' timeline updates
and merges them with normal status updates.  Normally, only replies from
friends are displayed.  This provides the display of @replies from
users not followed.

C<check_replies> adds an API call, counted against Twitter's rate limit
every L</"twitter_retry"> seconds.

This also has the effect of adding senders of @replies to the channel,
even though they are not followed.

=cut

has check_replies => ( isa => 'Bool', is => 'rw', default => 0 );

=item check_direct_messages

(Optional) If true, checks for direct messages in each timeline polling cycle.


C<check_direct_messages> adds an API call, counted against Twitter's rate limit
every L</"twitter_retry"> seconds.

=cut

has check_direct_messages => ( isa => 'Bool', is => 'rw', default => 0 );

=item log_channel

(Optional) If specified, twirc will post log messages to this channel.

=cut

has log_channel => ( isa => 'Str', is => 'ro' );

=item state_file

(Optional) File used to store state information between sessions, including last message read for
replies, direct messages, and timelines.

=cut

has state_file => ( isa => 'Str', is => 'ro' );

=item verbose_refresh

(Optional) If set (1), when a refresh (whether automatic or the result of the
L</"refresh"> command) finds no new messages, a notice to that effect will be
written to the channel.

=cut

has verbose_refresh => ( isa => 'Bool', is => 'rw', default => 0 );

=item plugins

(Optional) An array of plugin objects.

=cut

has plugins => ( isa => 'ArrayRef[Object]', is => 'ro', default => sub { [] } );

=back


=cut

has _ircd => (
       accessor => 'ircd', isa => 'POE::Component::Server::IRC', is => 'rw', weak_ref => 1 );
has _twitter => ( isa => 'Net::Twitter', is => 'rw' );
has _users_by_nick => (
    metaclass => 'Collection::Hash',
    isa => 'HashRef[HashRef]',
    is => 'rw',
    default => sub { {} },
    provides => {
        set      => 'set_user_by_nick',
        get      => 'get_user_by_nick',
        empty    => 'has_users_by_nick',
        count    => 'num_users_by_nick',
        'delete' => 'delete_user_by_nick',
        'keys'   => 'user_nicks',
    },
);

has _users_by_id => (
    metaclass => 'Collection::Hash',
    isa => 'HashRef[HashRef]',
    is  => 'rw',
    default => sub { {} },
    provides => {
        set      => 'set_user_by_id',
        get      => 'get_user_by_id',
        'delete' => 'delete_user_by_id',
    },
);

has _joined => (
       accessor => 'joined', isa => 'Bool', is => 'rw', default => 0 );
has _tweet_stack => (
       accessor => 'tweet_stack', isa => 'ArrayRef[HashRef]', is => 'rw', default => sub { [] } );
has _dm_stack => (
       accessor => 'dm_stack', isa => 'ArrayRef[HashRef]', is => 'rw', default => sub { [] } );

has _stash => (
        accessor  => 'stash',
        isa       => 'HashRef',
        is        => 'rw',
        predicate => 'has_stash',
        clearer   => 'clear_stash',
);

has _state => (
        accessor => 'state',
        isa      => 'POE::Component::Server::Twirc::State',
        is       => 'rw',
        builder  => '_build_state',
        lazy     => 1,
);

sub _build_state { POE::Component::Server::Twirc::State->new }

has _unread_posts => ( isa => 'HashRef', is => 'rw', default => sub { {} } );
has _topic_id     => ( isa => 'Int', is => 'rw', default => 0 );

sub twitter {
    my ($self, $method, @args) = @_;

    # Get our own NT object so we can check get_error
    my $nt = $self->_twitter->clone;
    my $r = eval { $nt->$method(@args) };

    # synthesize an error (broken twitter api!)
    if ( $r && ref($r) eq 'HASH' && exists $r->{error} ) {
        $nt->{response_error} = $r;
        undef $r;
    }

    unless ( defined $r ) {
        my $error = $nt->get_error;
        if ( ref $error ) {
            if ( ref($error) eq 'HASH' && exists $error->{error} ) {
                $error = $error->{error};
            }
            else {
                $error = 'Unexpected error type ' . ref($error);
            }
        }
        $error = $nt->http_code == 502 ? 'Fail Whale' : '[' . $nt->http_code . '] ' . $error;
        $error = $self->twitter_error("$method ->  $error");
    }

    return $r;
}

sub post_ircd {
    my $self = shift;
    $self->ircd->yield(@_);
}

sub bot_says  {
    my ($self, $channel, $text) = @_;

    $self->post_ircd('daemon_cmd_privmsg', $self->irc_botname, $channel, $text);
};

sub bot_notice {
    my ($self, $channel, $text) = @_;

    $self->post_ircd(daemon_cmd_notice => $self->irc_botname, $channel, $text);
}


sub twitter_error {
    my ($self, $text) = @_;

    $self->bot_notice($self->irc_channel, "Twitter error: $text");
};

# set topic from status, iff newest status
sub set_topic {
    my ($self, $status) = @_;

    # only set the topic if it's newer than the last topic
    return unless $status->{id} > $self->_topic_id;

    $self->_topic_id($status->{id});
    $self->post_ircd(daemon_cmd_topic => $self->irc_botname, $self->irc_channel,
           decode_entities($status->{text}));
};

# match any nick
sub nicks_alternation {
    my $self = shift;

    return join '|', map quotemeta, $self->user_nicks;
}

sub add_user {
    my ($self, $user) = @_;

    $self->set_user_by_nick($user->{screen_name}, $user);
    $self->set_user_by_id($user->{id}, $user);
}

sub delete_user {
    my ($self, $user) = @_;

    my ($id, $nick) = @{$user}{qw/id screen_name/};
    $self->delete_user_by_id($id);
    $self->delete_user_by_nick($nick);
}

sub START {
    my ($self) = @_;

    $self->ircd(
        POE::Component::Server::IRC->spawn(
            config => {
                servername => $self->irc_server_name,
                nicklen    => 15,
                network    => 'SimpleNET'
            },
            inline_states => {
                _stop  => sub { $self->log->debug('[ircd:stop]') },
            },
        )
    );

    # register ircd to receive events
    $self->post_ircd('register' );
    $self->ircd->add_auth(
        mask     => $self->irc_mask,
        password => $self->irc_password,
    );
    $self->post_ircd('add_listener', port     => $self->irc_server_port,
                                     bindaddr => $self->irc_server_bindaddr);

    # add super user
    $self->post_ircd(
        add_spoofed_nick =>
        { nick => $self->irc_botname, ircname => $self->irc_botircname }
    );
    $self->post_ircd(daemon_cmd_join => $self->irc_botname, $self->irc_channel);

    # logging
    if ( $self->log_channel ) {
        $self->post_ircd(daemon_cmd_join => $self->irc_botname, $self->log_channel);
        my $logger = Log::Log4perl->get_logger('');
        my $appender = Log::Log4perl::Appender->new(
            'POE::Component::Server::Twirc::LogAppender',
            name        => 'twirc-logger',
            ircd        => $self->ircd,
            irc_botname => $self->irc_botname,
            irc_channel => $self->log_channel,
        );
        $logger->add_appender($appender);
    }

    $self->yield('friends');
    $self->yield('user_timeline'); # for topic setting
    $self->yield('delay_friends_timeline');

    $self->_twitter(Net::Twitter->new(
        %{ $self->twitter_args },
        useragent_class => 'LWP::UserAgent::POE',
        username  => $self->twitter_username,
        password  => $self->twitter_password,
        useragent => "twirc/$VERSION",
        source    => 'twircgw',
    ));

    if ( $self->state_file && -r $self->state_file ) {
        eval {
            $self->state(POE::Component::Server::Twirc::State->load($self->state_file))
        };
        if ( $@ ) {
            $@ =~ s/ at .*//s;
            $self->log->error($@);
        }
    }

    return $self;
}

# Without detaching the ircd child session, the application will not
# shut down.  Bug in PoCo::Server::IRC?
event _child => sub {
    my ($self, $kernel, $event, $child) = @_[OBJECT, KERNEL, ARG0, ARG1];

    $self->log->debug("[_child] $event $child");
    $kernel->detach_child($child) if $event eq 'create';
};

event poco_shutdown => sub {
    my ($self) = @_;

    $self->log->debug("[poco_shutdown]");
    $_[KERNEL]->alarm_remove_all();
    $self->post_ircd('unregister');
    $self->post_ircd('shutdown');
    if ( $self->state_file ) {
        eval { $self->state->store($self->state_file) };
        if ( $@ ) {
            $@ =~ s/ at .*//s;
            $self->log->error($@);
        }
    }
};

########################################################################
# IRC events
########################################################################

event ircd_daemon_nick => sub {
    my ($self, $sender, $nick) = @_[OBJECT, SENDER, ARG0];

    $self->log->debug("[ircd_daemon_nick] $nick");

    # if it's a nick change, we only get ARG0 and ARG1
    return unless defined $_[ARG2];

    return if $nick eq $self->irc_botname;

    # Abuse!  Calling the private implementation of ircd to force-join the connecting
    # user to the twitter channel. ircd set's it's heap to $self: see ircd's perldoc.
    $sender->get_heap()->_daemon_cmd_join($nick, $self->irc_channel);
};

event ircd_daemon_join => sub {
    my($self, $sender, $user, $ch) = @_[OBJECT, SENDER, ARG0, ARG1];

    $self->log->debug("[ircd_daemon_join] $user, $ch");
    return unless my($nick) = $user =~ /^([^!]+)!/;
    return if $self->get_user_by_nick($nick);
    return if $nick eq $self->irc_botname;
    return if $nick eq $self->twitter_alias;

    if ( $ch eq $self->irc_channel ) {
        $self->joined(1);
        $self->log->debug("    joined!");
        $self->yield('display_direct_messages');
        $self->yield('throttle_messages');
        return;
    }
    elsif ( $self->log_channel && $ch eq $self->log_channel ) {
        my $appender = Log::Log4perl->appender_by_name('twirc-logger');
        $appender->dump_history;
    }
    else {
        $self->log->debug("    ** part **");
        # only one channel allowed
        $sender->get_heap()->_daemon_cmd_part($nick, $ch);
    }
};

event ircd_daemon_part => sub {
    my($self, $user_name, $ch) = @_[OBJECT, ARG0, ARG1];

    return unless my($nick) = $user_name =~ /^([^!]+)!/;
    return if $nick eq $self->irc_botname;

    $self->delete_user($self->get_user_by_nick($nick));

    $self->joined(0) if $ch eq $self->irc_channel && $nick eq $self->irc_nickname;
};

event ircd_daemon_quit => sub {
    my($self, $user) = @_[OBJECT, ARG0];

    $self->log->debug("[ircd_daemon_quit]");
    return unless my($nick) = $user =~ /^([^!]+)!/;
    return if $self->get_user_by_nick($nick);
    return if $nick eq $self->irc_botname;

    $self->joined(0);
    $self->yield('poco_shutdown');
};

event ircd_daemon_public => sub {
    my ($self, $user, $channel, $text) = @_[OBJECT, ARG0, ARG1, ARG2];

    return unless $channel eq $self->irc_channel;

    $text =~ s/\s+$//;

    my $nick = ( $user =~ m/^(.*)!/)[0];

    $self->log->debug("[ircd_daemon_public] $nick: $text");
    return unless $nick eq $self->irc_nickname;

    # give any command handler a shot
    if ( $self->has_stash ) {
        $self->log->debug("stash exists...");
        my $handler = delete $self->stash->{handler};
        if ( $handler ) {
            return if $self->$handler($channel, $text); # handled
        }
        else {
            $self->log->error("stash exsits with no handler");
        }
        # the user ignored a command completion request, kill it
        $self->clear_stash;
    }

    for my $plugin ( @{$self->plugins} ) {
        $plugin->preprocess($self, $channel, $nick, \$text) && last
            if $plugin->can('preprocess');
    }

    # treat "nick: ..." as "post @nick ..."
    my $nick_alternation = $self->nicks_alternation;
    $text =~ s/^(?:post\s+)?($nick_alternation):\s+/post \@$1 /i;

    my ($command, $argstr) = split /\s+/, $text, 2;
    if ( $command =~ /^\w+$/ ) {
        my $event = "cmd_$command";

        # Give each plugin a opportunity:
        # - Plugins return true if they swallow the event; false to continue
        #   the processing chain.
        # - Plugins can modify the text, so pass a ref.
        for my $plugin ( @{$self->plugins} ) {
            $plugin->$event($self, $channel, $nick, \$argstr) && return
                if $plugin->can($event);
        }
       if ( $self->can($event) ) {
            $self->yield($event, $channel, $argstr);
        }
        else {
            $self->bot_says($channel, qq/I don't understand "$command". Try "help"./)
        }
    }
    else {
        $self->bot_says($channel, qq/That doesn't look like a command. Try "help"./);
    }
};

event ircd_daemon_privmsg => sub {
    my ($self, $user, $target_nick, $text) = @_[OBJECT, ARG0..ARG2];

    # owning user is the only one allowed to send direct messages
    my $me = $self->irc_nickname;
    return unless $user =~ /^\Q$me\E!/;

    unless ( $self->get_user_by_nick($target_nick) ) {
        # TODO: handle the error the way IRC would?? (What channel?)
        $self->bot_says($self->irc_channel, qq/You don't appear to be following $target_nick; message not sent./);
        return;
    }

    unless ( $self->twitter(new_direct_message => { user => $target_nick, text => $text }) ) {
        # TODO what channel?
        $self->bot_says($self->irc_channel, "new_direct_message failed.");
    }
};

########################################################################
# Twitter events
########################################################################

# This is the main loop; check for updates every twitter_retry seconds.
event delay_friends_timeline => sub {
    my ($self) = @_;

    $self->yield('direct_messages') if $self->check_direct_messages;
    $self->yield('friends_timeline');
    $_[KERNEL]->delay(delay_friends_timeline => $self->twitter_retry);
};

event throttle_messages => sub {
    my ($self) = @_;

    $self->log->debug("[throttle_messages] ", scalar @{$self->tweet_stack}, " messages");

    for my $entry ( @{$self->tweet_stack} ) {
        my @lines = split /[\r\n]+/, $entry->{text};
        $self->post_ircd(daemon_cmd_privmsg => $entry->{name}, $self->irc_channel, $_)
            for @lines;
    }

    $self->tweet_stack([]);
};

# Add friends to the channel
event friends => sub {
    my ($self, $page ) = @_[OBJECT, ARG0];

    my $retry = $self->twitter_retry_on_error;

    $self->log->debug("[twitter:friends] calling...");
    $page ||= 1;
    for (;;) {
        my $friends = $self->twitter(friends => {page => $page});
        unless ( $friends ) {
            $_[KERNEL]->delay(friends => $retry, $page);
            return;
        }
        $self->log->debug("    friends returned ", scalar @$friends, " friends");

        ++$page;

        # Current API gets 100 friends per page.  If we have exactly 100 friends
        # we have to try again with page=2 and we should get (I'm assuming, here)
        # an empty arrayref.  What if the API changes to 200, etc.?  Might as well
        # just loop until we get an empty arrayref.  That will handle either case.
        last unless @$friends;

        for my $friend ( @$friends ) {
            my ($id, $nick, $name) = @{$friend}{qw/id screen_name name/};

            next if $self->get_user_by_id($id);
            $self->post_ircd(add_spoofed_nick => { nick => $nick, ircname => $name });
            $self->post_ircd(daemon_cmd_join => $nick, $self->irc_channel);
            $self->add_user($friend);
        }
    }
    $self->yield('followers');
};

# Give friends who are also followers voice; it's just a visual hint to the user.
event followers => sub {
    my ($self, $page ) = @_[OBJECT, ARG0];

    my $retry = $self->twitter_retry_on_error;

    $self->log->debug("[twitter:followers] calling...");
    $page ||= 1;
    while ( my $followers = $self->twitter(followers => {page => $page}) ) {
        $self->log->debug("    page: $page");
        unless ( $followers ) {
            $self->twitter_error("request for followers failed; retrying in $retry seconds");
            $_[KERNEL]->delay(followers => $retry, $page);
            return;
        }
        ++$page;

        $self->log->debug("    followers returned ", scalar @$followers, " followers");

        # see comments for event friends
        last unless @$followers;

        for my $follower ( @$followers ) {
            my $nick = $follower->{screen_name};
            if ( $self->get_user_by_nick($nick) ) {
                $self->post_ircd(daemon_cmd_mode =>
                    $self->irc_botname, $self->irc_channel, '+v', $nick);
            }
        }
    }
};

event direct_messages => sub {
    my ($self) = @_;

    # We don't want to flood the user with DMs, so if this is the first time,
    # i.e., no DM id in saved state, just set the high water mark and return.
    unless ( $self->state->direct_message_id ) {
        if ( my $high_water = $self->twitter('direct_messages') ) {
            $self->state->direct_message_id($high_water->[0]{id}) if @$high_water;
        }
        return;
    }

    my $since_id = $self->state->direct_message_id || 1;
    my $messages = $self->twitter(direct_messages => { since_id => $since_id }) || return;

    if ( @$messages ) {
        $self->state->direct_message_id($messages->[0]{id})
            if $messages->[0]{id} > $since_id; # lack of faith in twitterapi

        for my $msg ( reverse @$messages ) {
            # workarond twitter bug where since_id parameter is ignored:
            next unless $msg->{id} > $since_id;

            my ($nick, $ircname) = @{$msg->{sender}}{qw/screen_name name/};
            unless ( $self->get_user_by_nick($nick) ) {
                $self->log->warn("Joining $nick from a direct message; expected $nick already joined.");
                $self->post_ircd(add_spoofed_nick => { nick => $nick, ircname => $ircname });
                $self->post_ircd(daemon_cmd_join => $nick, $self->irc_channel);
                $self->add_user({
                    # don't have a status to store
                    id => $msg->{sender_id},
                    screen_name => $msg->{sender_screen_name}
                });
            }

            push @{$self->dm_stack}, { name => $nick, text => $msg->{text} };
        }
        $self->yield('display_direct_messages') if $self->joined;
    }
};

event display_direct_messages => sub {
    my ($self) = @_;

    while ( my $msg = shift @{$self->dm_stack} ) {
        my @lines = split /\r?\n/, $msg->{text};
        $self->post_ircd(daemon_cmd_privmsg => $msg->{name}, $self->irc_nickname, $_)
            for @lines;
    }
};

event friends_timeline => sub {
    my ($self) = @_;

    $self->log->debug("[friends_timeline]");

    my $since_id = $self->state->friends_timeline_id || 1;
    my $statuses = $self->twitter(friends_timeline => { since_id => $since_id }) || return;

    $self->log->debug("    friends_timeline returned ", scalar @$statuses, " statuses");
    $self->state->friends_timeline_id($statuses->[0]{id})
        if @$statuses && $statuses->[0]{id} > $since_id;  # lack of faith in twitterapi

    $statuses = $self->merge_replies($statuses);

    my $channel = $self->irc_channel;
    my $new_topic;
    for my $status (reverse @{ $statuses }) {
        # Work around twitter api bug where since_id is ignored. (I haven't seen this bug
        # with friends_timeline---only with direct_messages and replies.  Adding the workaround
        # for friends_timeline proactively.)
        next unless $status->{id} > $since_id;

        my ($id, $name, $ircname) = @{$status->{user}}{qw/id screen_name name/};
        my $text = decode_entities($status->{text});

        # alias our twitter_name if configured
        # (to avoid a collision in case our twitter screen name and irc nick are the same)
        $self->log->debug("    \$name = $name, \$twitter_name = "), $self->twitter_screen_name;

        # message from self
        if ( $name eq $self->twitter_screen_name ) {
            $self->state->user_timeline_id($status->{id})
                if $status->{id} > $self->state->user_timeline_id; # lack of faith in twitterapi
            $new_topic = $status unless $status->{text} =~ /^\s*\@/;

            # TODO: is this even necessary? Can we just send a privmsg from a real user?
            $name = $self->twitter_alias if $self->twitter_alias;

            # if we posted this status from twirc, we've already seen it
            my $seen = delete $self->_unread_posts->{$status->{id}};
            next if $seen && !$self->echo_posts;
        }

        my $user = $self->get_user_by_id($id);
        if ( !$user ) {
            # new user
            $self->post_ircd(add_spoofed_nick => { nick => $name, ircname => $ircname });
            $self->post_ircd(daemon_cmd_join => $name, $channel);
        }
        elsif ( $user->{screen_name} ne $name ) {
            # nick change
            $self->delete_user_by_nick($user->{id});
            $self->post_ircd(daemon_cmd_nick => $user->{screen_name}, $name);
        }

        $self->add_user({
            id => $status->{user}->{id},
            screen_name => $name,
        });

        $self->log->debug("    { $name, $text }");
        push @{ $self->tweet_stack }, { name => $name, text => $text }
    }

    if ( @$statuses == 0 && $self->verbose_refresh ) {
      $self->bot_notice($channel, "That refresh didn't get any new tweets.");
    }

    $self->set_topic($new_topic) if $new_topic;
    $self->yield('throttle_messages') if $self->joined;
    $self->yield('poll_cleanup');
};

# handle cleanup after the important work has had a chance to complete
event poll_cleanup => sub {
    my ($self) = @_;

    # store state
    if ( $self->state_file ) {
        eval { $self->state->store($self->state_file) };
        if ( $@ ) {
            $@ =~ s/ at .*//s;
            $self->log->error($@);
        }
    }

    # It is possible to get here with _unread_posts populated, for instance, if a post
    # has been sent *during* processing of the most recent poll results.  However, we
    # should never have an _uread post older than friends_timeline_id.
    for my $id ( keys %{$self->_unread_posts} ) {
        if ( $id <= $self->state->friends_timeline_id ) {
            $self->log->error("recent post missing from the feed: $id");
            delete $self->_unread_posts->{$id};
        }
    }
};

sub merge_replies {
    my ($self, $statuses) = @_;
    return $statuses unless $self->check_replies;

    # TODO: find a better way to initialize this??
    unless ( $self->state->reply_id ) {
        $self->state->reply_id(
            @$statuses ? $statuses->[-1]{id} : $self->state->user_timeline_id
         );
    }

    my $since_id = $self->state->reply_id || 1;
    my $replies = $self->twitter(replies => { since_id => $since_id });
    if ( $replies ) {
        if ( @$replies ) {
            $self->log->debug("[merge_replies] ", scalar @$replies, " replies");

            $self->state->reply_id($replies->[0]{id})
                if $replies->[0]{id} > $since_id; # lack of faith in twitterapi

            # TODO: clarification needed: I'm assuming we get replies
            # from friends in *both* friends_timeline and replies,
            # so, we need to weed them.
            my %seen = map { ($_->{id}, $_) }
                       @{$statuses},
                       # work around a twitter api bug where the since_id param is ignored
                       grep { $_->{id} > $since_id } @{$replies};

            $statuses = [ sort { $b->{id} <=> $a->{id} } values %seen ];
        }
    }
    return $statuses;
}

event user_timeline => sub {
    my ($self) = @_;

    $self->log->debug("[user_timetline] calling...");
    # Work around a twitter api bug by passing id; without it, sometimes the wrong users statuses
    # are returned.
    my $statuses = $self->twitter(user_timeline => { id =>  $self->twitter_screen_name });
    unless ( $statuses ) {
        $_[KERNEL]->delay(user_timeline => 60);
    }
    $self->log->debug("    urser_timeline returned");

    return unless @$statuses;

    for my $status ( @$statuses ) {
        # skip @replies
        unless ( $status->{text} =~ /^\s*\@/ ) {
            $self->set_topic($status);
            return;
        }
    }

    #couldn't find an non-@reply status, punt
    $self->set_topic($statuses->[0]);
};

########################################################################
# Commands
########################################################################

=head2 COMMANDS

Commands are entered as public messages in the IRC channel in the form:

    command arg1 arg2 ... argn

Where the arguments, if any, depend upon the command.

=over 4

=item post I<status>

Post a status update.  E.g.,

    post Now cooking tweets with twirc!

=cut

event cmd_post => sub {
    my ($self, $channel, $text) = @_[OBJECT, ARG0, ARG1];

    $self->log->debug("[cmd_post_status]");

    if ( (my $n = length($text) - 140) > 0 ) {
        $self->bot_says($channel, "Message not sent; $n characters too long. Limit is 140 characters.");
        return;
    }

    my $status = $self->twitter(update => $text) || return;

    $self->log->debug("    update returned $status");

    $self->set_topic($status) unless $status->{text} =~ /^\s*\@/;
    $self->_unread_posts->{$status->{id}} = 1;
};

=item follow I<id>

Follow a new Twitter user, I<id>.  In Twitter parlance, this creates a friendship.

=cut

event cmd_follow => sub {
    my ($self, $channel, $id) = @_[OBJECT, ARG0, ARG1];

    if ( $id !~ /^\w+$/ ) {
        $self->bot_says($channel, qq/"$id" doesn't look like a user ID to me./);
        return;
    }

    my $friend = $self->twitter(create_friend => $id) || return;

    my ($nick, $name) = @{$friend}{qw/screen_name name/};
    $self->post_ircd('add_spoofed_nick', { nick => $nick, ircname => $name });
    $self->post_ircd(daemon_cmd_join => $name, $self->irc_channel);
    $self->add_user($friend);

    # work around back compat bug in Net::Twitter 2.01
    my @args = ($nick, $self->twitter_screen_name);
    @args = ( { user_a => $args[0], user_b => $args[1] } ) if Net::Twitter->VERSION >= 2.00;

    if ( $self->twitter(relationship_exists => @args) ) {
        $self->post_ircd(daemon_cmd_mode =>
            $self->irc_botname, $self->irc_channel, '+v', $nick);
        $self->bot_notice($channel, qq/Now following $id./);
    }
};

=item unfollow I<id>

Stop following Twitter user I<id>.  In Twitter, parlance, this destroys a
friendship.

=cut

event cmd_unfollow => sub {
    my ($self, $channel, $id) = @_[OBJECT, ARG0, ARG1];

    if ( !$self->get_user_by_nick($id) ) {
        $self->bot_says($channel, qq/You don't appear to be following $id./);
        return;
    }

    my $friend = $self->twitter(destroy_friend => $id) || return;

    $self->post_ircd(daemon_cmd_part => $id, $self->irc_channel);
    $self->post_ircd(del_spooked_nick => $id);
    $self->bot_notice($channel, qq/No longer following $id./);
};

=item block I<id>

Block Twitter user I<id>.

=cut

event cmd_block => sub {
    my ($self, $channel, $id) = @_[OBJECT, ARG0, ARG1];

    if ( $id !~ /^\w+$/ ) {
        $self->bot_says($channel, qq/"$id" doesn't look like a user ID to me./);
        return;
    }

    $self->twitter(create_block => $id) || return;

    if ( $self->get_user_by_nick($id) ) {
        $self->post_ircd(daemon_cmd_mode =>
            $self->irc_botname, $self->irc_channel, '-v', $id);
        $self->bot_notice($channel, qq/Blocked $id./);
    }
};

=item unblock I<id>

Stop blocking Twitter user I<id>.

=cut

event cmd_unblock => sub {
    my ($self, $channel, $id) = @_[OBJECT, ARG0, ARG1];

    if ( $id !~ /^\w+$/ ) {
        $self->bot_says($channel, qq/"$id" doesn't look like a user ID to me./);
        return;
    }

    $self->twitter(destroy_block => $id) || return;

    if ( $self->get_user_by_nick($id) ) {
        $self->post_ircd(daemon_cmd_mode =>
            $self->irc_botname, $self->irc_channel, '+v', $id);
        $self->bot_notice($channel, qq/Unblocked $id./);
    }
};

=item whois I<id>

Displays information about Twitter user I<id>, including name, location, and
description.

=cut

event cmd_whois => sub {
    my ($self, $channel, $id) = @_[OBJECT, ARG0, ARG1];

    $self->log->debug("[cmd_whois] $id");

    my $user = $self->get_user_by_nick($id);
    unless ( $user ) {
        $self->log->debug("     $id not in users; fetching");
        my $arg = Email::Valid->address($id) ? { email => $id } : { id => $id };
        $user = $self->twitter(show_user => $arg) || return;
    }
    if ( $user ) {
        $self->bot_says($channel, "$user->{screen_name} [$user->{id}]: $user->{name}, $user->{location}");
        for ( @{$user}{qw/description url/} ) {
            $self->bot_says($channel, $_) if $_;
        }
    }
    else {
        $self->bot_says($channel, "I don't know $id.");
    }
};

=item notify I<on|off> I<id ...>

Turns device notifications on or off for the list of Twitter IDs.

=cut

event cmd_notify => sub {
    my ($self, $channel, $argstr) = @_[OBJECT, ARG0, ARG1];

    my @nicks = split /\s+/, $argstr;
    my $onoff = shift @nicks;

    unless ( $onoff && $onoff =~ /^on|off$/ ) {
        $self->bot_says($channel, "Usage: notify on|off nick[ nick [...]]");
        return;
    }

    my $method = $onoff eq 'on' ? 'enable_notifications' : 'disable_notifications';
    for my $nick ( @nicks ) {
        unless ( $self->twitter($method => { id => $nick }) ) {
            $self->bot_says($channel, "notify $onoff failed for $nick");
        }
    }
};

=item favorite I<friend> [I<count>]

Mark I<friend>'s tweet as a favorite.  Optionally, specify the number of tweets
to display for selection with I<count> (Defaults to 3.)

=cut

event cmd_favorite => sub {
    my ($self, $channel, $args) = @_[OBJECT, ARG0, ARG1];

    my ($nick, $count) = split /\s+/, $args;
    $count ||= $self->favorites_count;

    $self->log->debug("[cmd_favorite] $nick");

    unless ( $self->get_user_by_nick($nick) ) {
        $self->bot_says($channel, "You're not following $nick.");
        return;
    }

    my $recent = $self->twitter(user_timeline => { id => $nick, count => $count }) || return;
    if ( @$recent == 0 ) {
        $self->bot_says($channel, "$nick has no recent tweets");
        return;
    }

    $self->stash({
        favorite_candidates => [ map $_->{id}, @$recent ],
        handler => 'handle_favorite',
    });

    $self->bot_says($channel, 'Which tweet?');
    for ( 1..@$recent ) {
        $self->bot_says($channel, "[$_] " . truncstr($recent->[$_ - 1]{text}, $self->truncate_to));
    }
};

sub handle_favorite {
    my ($self, $channel, $index) = @_;

    $self->log->debug("[handle_favorite] $index");

    my @favorite_candidates = @{$self->stash->{favorite_candidates} || []};
    if ( $index =~ /^\d+$/ && 0 < $index && $index <= @favorite_candidates ) {
        if ( $self->twitter(create_favorite => { id => $favorite_candidates[$index - 1] }) ) {
            $self->bot_notice($channel, 'favorite added');
        }
        $self->clear_stash;
        return 1; # handled
    }
    return 0; # unhandled
};

=item check_replies I<on|off>

Turns reply checking on or off.  See L</"check_replies"> in configuration.

=cut

event cmd_check_replies => sub {
    my ($self, $channel, $onoff) = @_[OBJECT, ARG0, ARG1];

    unless ( $onoff && $onoff =~ /^on|off$/ ) {
        $self->bot_says($channel, "Usage: check_replies on|off");
        return;
    }
    $self->check_replies($onoff eq 'on' ? 1 : 0);
};

=item check_direct_messages I<on|off>

Turns direct message checking on or off.  See L</"check_direct_messages"> in configuration.

=cut

event cmd_check_direct_messages => sub {
    my ($self, $channel, $onoff) = @_[OBJECT, ARG0, ARG1];

    unless ( $onoff && $onoff =~ /^on|off$/ ) {
        $self->bot_says($channel, "Usage: check_direct_messages on|off");
        return;
    }
    $self->check_direct_messages($onoff eq 'on' ? 1 : 0);
};

=item rate_limit_status

Displays the remaining number of API requests available in the current hour.

=cut

event cmd_rate_limit_status => sub {
    my ($self, $channel) = @_[OBJECT, ARG0];

    if ( my $r = $self->twitter('rate_limit_status') ) {
        my $reset_time = sprintf "%02d:%02d:%02d", (localtime $r->{reset_time_in_seconds})[2,1,0];
        my $seconds_remaning = $r->{reset_time_in_seconds} - time;
        my $time_remaning = sprintf "%d:%02d", int($seconds_remaning / 60), $seconds_remaning % 60;
        $self->bot_says($channel, <<"");
$r->{remaining_hits} API calls remaining for the next $time_remaning (until $reset_time), hourly limit is $r->{hourly_limit}

    }
};

=item help

Display a simple help message

=cut

event cmd_help => sub {
    my ($self, $channel, $argstr)=@_[OBJECT, ARG0, ARG1];
    $self->bot_says($channel, "Available commands:");
    $self->bot_says($channel, join ' ' => sort qw/
        post follow unfollow block unblock whois notify refresh favorite
        check_replies rate_limit_status verbose_refresh
    /);
    $self->bot_says($channel, '/msg nick for a direct message.')
};

event cmd_refresh => sub {
    my ($self) = @_;

    $self->yield('delay_friends_timeline');
};

=item verbose_refresh I<on|off>

Turns C<verbose_refresh> on or off.  See L</"verbose_refresh"> in configuration.

=cut

event cmd_verbose_refresh => sub {
    my ($self, $channel, $onoff) = @_[OBJECT, ARG0, ARG1];

    unless ( $onoff && $onoff =~ /^on|off$/ ) {
        $self->bot_says($channel, "Usage: verbose_refresh on|off");
        return;
    }
    $self->verbose_refresh($onoff eq 'on' ? 1 : 0);
};

1;

__END__

=item /msg I<id> I<text>

Sends a direct message to Twitter user I<id> using an IRC private message.

=back

=head1 SEE ALSO

L<App::Twirc>

=head1 AUTHOR

Marc Mims <marc@questright.com>

=head1 LICENSE

Copyright (c) 2008 Marc Mims

You may distribute this code and/or modify it under the same terms as Perl itself.

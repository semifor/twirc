package POE::Component::Server::Twirc;
use MooseX::POE;

use MooseX::AttributeHelpers;
use LWP::UserAgent::POE;
use POE qw(Component::Server::IRC);
use Net::Twitter;
use Email::Valid;
use String::Truncate qw/elide/;
use POE::Component::Server::Twirc::LogAppender;
use POE::Component::Server::Twirc::State;
use Encode qw/decode/;
use Try::Tiny;
use Scalar::Util qw/reftype/;
use AnyEvent::Twitter::Stream;
use HTML::Entities;

with 'MooseX::Log::Log4perl';

our $VERSION = '0.13';

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

has twitter_screen_name => ( isa => 'Str', is => 'rw' );


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
has irc_server_bindaddr => ( isa => 'Str', is => 'ro', default => '' );

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

=item extra_net_twitter_traits

(Optional) Additional traits used to construct the Net::Twitter instance.

=cut

has extra_net_twitter_traits => (
    is      => 'ro',
    default => sub { [] },
);

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

=item log_channel

(Optional) If specified, twirc will post log messages to this channel.

=cut

has log_channel => ( isa => 'Str', is => 'ro' );

=item state_file

(Optional) File used to store state information between sessions, including last message read for
replies, direct messages, and timelines.

=cut

has state_file => ( isa => 'Str', is => 'ro' );

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
    isa => 'HashRef[HashRef|Object]',
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
    isa => 'HashRef[HashRef|Object]',
    is  => 'rw',
    default => sub { {} },
    provides => {
        set      => 'set_user_by_id',
        get      => 'get_user_by_id',
        'delete' => 'delete_user_by_id',
    },
);

has _joined => ( accessor => 'joined', isa => 'Bool', is => 'rw', default => 0 );

has _tweet_stack => (
       accessor => 'tweet_stack',
       isa      => 'ArrayRef[Object]',
       is       => 'rw',
       default  => sub { [] },
);
has _dm_stack => (
       accessor => 'dm_stack',
       isa      => 'ArrayRef[Object]',
       is       => 'rw',
       default  => sub { [] },
);

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

has client_encoding => ( isa => 'Str', is  => 'rw', default => sub { 'utf-8' } );

sub twitter {
    my ($self, $method, @args) = @_;

    my $r = try { $self->_twitter->$method(@args) }
    catch {
        if ( blessed $_ && $_->can('code') && $_->code == 502 ) {
            $_ = 'Fail Whale';
        }
        $self->twitter_error("$method -> $_");
        undef;
    };

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

my $zero_id = "0" x 19;
sub id_gt { id_cmp(@_) > 0 }

sub id_cmp {
    # Twitter now uses 64 bit ints for status IDs, so we use id_str to avoid trouble on
    # 32-bit platforms.  So we do string comparison on IDs after zero padding them to their
    # maximum length.
    my ( $a, $b ) = map substr($zero_id . $_, -19), @_;
    $a cmp $b;
}

# set topic from status, iff newest status
sub set_topic {
    my ($self, $text) = @_;

    $self->post_ircd(daemon_cmd_topic => $self->irc_botname, $self->irc_channel, $text);
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

    $self->delete_user_by_id($user->{id});
    $self->delete_user_by_nick($user->{screen_name});
}

sub _twitter_auth {
    # ROT13: Gjvggre qbrf abg jnag pbafhzre xrl/frperg vapyhqrq va bcra
    # fbhepr nccf. Gurl frrz gb guvax cebcevrgnel pbqr vf fnsre orpnhfr
    # gur pbafhzre perqragvnyf ner boshfpngrq.  Fb, jr'yy boshfpngr gurz
    # urer jvgu ebg13 naq jr'yy or "frpher" whfg yvxr n cebcevrgnel ncc.
    ( grep tr/a-zA-Z/n-za-mN-ZA-M/, map $_,
        pbafhzre_xrl     => 'ntqifMSFhMC0NdSWmBWgtN',
        pbafhzre_frperg  => 'CDDA2pAiDcjb6saxt0LLwezCBV97VPYGAF0LMa0oH',
    ),
}

sub _net_twitter_opts {
    my $self = shift;

    my %config = (
        $self->_twitter_auth,
        traits               => [qw/API::REST OAuth/],
        useragent_class      => 'LWP::UserAgent::POE',
        useragent            => "twirc/$VERSION",
        decode_html_entities => 1,
        %{ $self->twitter_args },
    );

    foreach my $plugin (@{$self->plugins}){
        if ($plugin->can('plugin_traits')) {
            push @{ $config{traits} }, $plugin->plugin_traits();
        }
    }

    my %unique_traits = map { $_ => undef }
        @{ $config{traits} },
        @{ $self->extra_net_twitter_traits };
    $config{traits} = [ keys %unique_traits ];

    return %config;
}

has twitter_stream_watcher => is => 'rw', clearer => 'disconnect_twitter_stream',
        predicate => 'has_twitter_stream_watcher';

sub connect_twitter_stream {
    my $self = shift;

    my $w; $w = AnyEvent::Twitter::Stream->new(
        $self->_twitter_auth,
        token        => $self->state->access_token,
        token_secret => $self->state->access_token_secret,
        method       => 'userstream',
        on_connect   => sub {
            $self->twitter_stream_watcher($w);
            $self->log->info('Connected to Twitter');
        },
        on_eof       => sub {
            $self->log->debug("on_eof");
            $self->bot_notice($self->irc_channel, "Twitter stream disconnected");
            $self->connect_twitter_stream if $self->has_twitter_stream_watcher;
        },
        on_error   => sub {
            my $e = shift;
            $self->log->debug("on_error: $e");
            $self->bot_notice($self->irc_channel, "Twitter stream error: $e");
        },
        on_keepalive   => sub {
            $self->log->debug("on_keepalive");
        },
        on_friends   => sub {
            $self->log->debug("on_friends: ", JSON->new->encode(@_));
            $self->yield(friends_ids => shift);
        },
        on_event     => sub {
            $self->log->debug("on_event: ", JSON->new->encode(@_));
        },
        on_tweet     => sub {
            $self->log->debug("on_tweet");
            $self->yield(display_status => shift);
        },
        on_delete    => sub {
            $self->log->debug("on_delete");
        },
    );
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

    if ( $self->state_file && -r $self->state_file ) {
        try {
            $self->state(POE::Component::Server::Twirc::State->load($self->state_file))
        }
        catch {
            s/ at .*//s;
            $self->log->error($_);
        };
    }

    $self->state->access_token && $self->state->access_token_secret || $self->xauth;

    $self->_twitter(Net::Twitter->new(
        $self->_net_twitter_opts()
    ));

    $self->_twitter->access_token($self->state->access_token);
    $self->_twitter->access_token_secret($self->state->access_token_secret);

    POE::Kernel->sig(TERM => 'poco_shutdown');
    POE::Kernel->sig(INT  => 'poco_shutdown');

    $self->connect_twitter_stream;

    $self->yield('get_topic');

    return $self;
}

# Without detaching the ircd child session, the application will not
# shut down.  Bug in PoCo::Server::IRC?
event _child => sub {
    my ($self, $kernel, $event, $child) = @_[OBJECT, KERNEL, ARG0, ARG1];

    $self->log->debug("[_child] $event $child");
    $kernel->detach_child($child) if $event eq 'create';
};

sub xauth {
    my $self = shift;

    # LWP::UserAgent::POE doesn't handle SSL, so we need a blocking UA
    my $nt = Net::Twitter->new(
        $self->_net_twitter_opts,
        useragent_class => 'LWP::UserAgent',
    );

    my ($token, $secret, $user_id, $screen_name) = try {
        $nt->xauth($self->twitter_username, $self->twitter_password);
    }
    catch {
        if ( /401 Unauthorize/ ) {
            die "Twitter login failed. Check your username and password.\n";
        }

        die "Twitter login failed: $_\n";
    };

    $self->twitter_screen_name($screen_name);

    $self->state->access_token($token);
    $self->state->access_token_secret($secret);
    try { $self->state->store($self->state_file) };
};

event poco_shutdown => sub {
    my ($self) = @_;

    $self->log->debug("[poco_shutdown]");
    $self->disconnect_twitter_stream;
    $_[KERNEL]->alarm_remove_all();
    $self->post_ircd('unregister');
    $self->post_ircd('shutdown');
    $_[KERNEL]->call($self->_twitter->ua->{poco_alias}, 'shutdown');
    if ( $self->state_file ) {
        try { $self->state->store($self->state_file) }
        catch {
            s/ at .*//s;
            $self->log->error($_);
        };
    }

    # TODO: Why does twirc often fail to shut down?
    # This is surely the WRONG thing to do, but hit the big red kill switch.
    exit 0;
};

event get_topic => sub {
    my $self = $_[OBJECT];

    if ( my $r = $self->twitter('verify_credentials',{ include_entities => 1 }) ) {
        if ( my $status = delete $$r{status} ) {
            $$status{user} = $r;
            $self->set_topic($self->formatted_status_text($status));
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

    if ( my $user = $self->get_user_by_nick($nick) ) {
        $self->delete_user($user);
    }

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

    $text = decode($self->client_encoding, $text);

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

    $text = decode($self->client_encoding, $text);

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

sub stale_after () { 7*24*3600 } # 1 week
sub is_stale {
    my ( $self, $user ) = @_;

    return time - $user->{FRESH} > $self->stale_after;
}

event friend_join => sub {
    my ( $self, $friend ) = @_[OBJECT, ARG0];

    $self->post_ircd(add_spoofed_nick => { nick => $friend->{screen_name}, ircname => $friend->{name} });
    $self->post_ircd(daemon_cmd_join => $friend->{screen_name}, $self->irc_channel);
    $self->add_user($friend);
};

event lookup_friends => sub {
    my ( $self, $ids ) = @_[OBJECT, ARG0];

    return unless @$ids;

    my $fresh = time;
    my $r = $self->twitter(lookup_users => { user_id => $ids });
    for my $friend ( @{$r || []} ) {
        delete $friend->{status};
        $friend->{FRESH} = $fresh;
        $self->state->friends->{$friend->{id}} = $friend;
        $self->yield(friend_join => $friend);
    }

    $self->state->store($self->state_file);
};

event get_followers_ids => sub {
    my ( $self ) = $_[OBJECT];

    for ( my $cursor = -1; $cursor; ) {
        if ( my $r = $self->twitter(followers_ids => { cursor => $cursor }) ) {
            for my $id ( @{$$r{ids}} ) {
                if ( my $friend = $self->get_user_by_id($id) ) {
                    $self->post_ircd(daemon_cmd_mode => $self->irc_botname, $self->irc_channel, '+v',
                        $friend->{screen_name});
                }
            }
            $cursor = $$r{next_cursor};
        }
        else {
            $cursor = 0;
        }
    }
};

sub formatted_status_text {
    my ( $self, $status ) = @_;

    my $is_retweet = !!$$status{retweeted_status};
    my $s = $$status{retweeted_status} || $status;
    my $text = $$s{text};
    for my $e ( reverse @{$$s{entities}{urls} || []} ) {
        my ($start, $end) = @{$$e{indices}};
        substr $text, $start, $end - $start, "[$$e{display_url}]($$e{url})";
    }

    decode_entities($text);

    $text = "RT \@$$s{user}{screen_name}: $text" if $is_retweet;

    return $text;
}

########################################################################
# Twitter events
########################################################################

event friends_ids => sub {
    my ( $self, $friends_ids ) = @_[OBJECT, ARG0];

    my $buffer = [];
    for my $id ( @$friends_ids ) {
        my $friend = $self->state->friends->{$id};
        if ( !$friend || $self->is_stale($friend) ) {
            push @$buffer, $id;
            if ( @$buffer == 100 ) {
                $self->yield(lookup_friends => $buffer);
                $buffer = [];
            }
        }
        else {
            $self->yield(friend_join => $friend);
        }
    }

    $self->yield(lookup_friends => $buffer);
    $self->yield('get_followers_ids');
};

event display_status => sub {
    my ( $self, $status ) = @_[OBJECT, ARG0];

    my $text = $self->formatted_status_text($status);
    my $name = $$status{user}{screen_name};
    if ( $name eq $self->irc_nickname ) {
        $name = $self->twitter_alias;
        $self->set_topic($text);
    }

    $self->log->debug("display_status: <$name> $text");
    $self->post_ircd(daemon_cmd_privmsg => $name, $self->irc_channel, $_) for split /[\r\n]+/, $text;
};

event direct_messages => sub {
    my ($self) = @_;

    # We don't want to flood the user with DMs, so if this is the first time,
    # i.e., no DM id in saved state, just set the high water mark and return.
    unless ( $self->state->direct_message_id ) {
        if ( my $high_water = $self->twitter('direct_messages') ) {
            $self->state->direct_message_id(@$high_water ? $high_water->[0]{id} : 1);
        }
        return;
    }

    my $since_id = $self->state->direct_message_id;
    my $messages = $self->twitter(direct_messages => { since_id => $since_id }) || return;

    if ( @$messages ) {
        $self->state->direct_message_id($messages->[0]{id})
            if $messages->[0]{id} > $since_id; # lack of faith in twitterapi

        while ( my $msg = pop @$messages ) {
            # workarond twitter bug where since_id parameter is ignored:
            next unless $$msg{id} > $since_id;

            my $nick = $msg->{sender}{screen_name};
            unless ( $self->get_user_by_nick($nick) ) {
                $self->log->warn("Joining $nick from a direct message; expected $nick already joined.");
                $self->post_ircd(add_spoofed_nick => { nick => $nick, ircname => $msg->{sender}{name} });
                $self->post_ircd(daemon_cmd_join => $nick, $self->irc_channel);
                $self->add_user($$msg{sender});
            }

            push @{$self->dm_stack}, $msg;
        }
        $self->yield('display_direct_messages') if $self->joined;
    }
};

event display_direct_messages => sub {
    my ($self) = @_;

    while ( my $msg = shift @{$self->dm_stack} ) {
        my $name = $$msg{sender_screen_name};
        $name = $self->twitter_alias if $name eq $self->irc_nickname;
        $self->post_ircd(daemon_cmd_privmsg => $name, $self->irc_nickname, $_)
            for split /\r?\n/, $$msg{text};
    }
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

    my $nick = $$friend{screen_name};
    my $name = $$friend{name};
    $self->post_ircd('add_spoofed_nick', { nick => $nick, ircname => $name });
    $self->post_ircd(daemon_cmd_join => $name, $self->irc_channel);
    $self->add_user($friend);

    my @args = ($nick, $self->twitter_screen_name);

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

    $self->twitter(destroy_friend => $id) || return;

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
        $self->bot_says(
            $channel, 
            sprintf('%s [%s]: %s, %s', @{$user}{qw/screen_name id name location description url/})
        );
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

=item favorite I<screen_name> [I<count>]

Mark a tweet as a favorite.  Specify the user by I<screen_name> and select from a
list of recent tweets. Optionally, specify the number of tweets to display for
selection with I<count> (Defaults to 3.)

=cut

event cmd_favorite => sub {
    my ($self, $channel, $args) = @_[OBJECT, ARG0, ARG1];

    my ($nick, $count) = split /\s+/, $args;
    $count ||= $self->favorites_count;

    $self->log->debug("[cmd_favorite] $nick");

    my $recent = $self->twitter(user_timeline => { screen_name => $nick, count => $count }) || return;
    if ( @$recent == 0 ) {
        $self->bot_says($channel, "$nick has no recent tweets");
        return;
    }

    $self->stash({
        handler    => '_handle_favorite',
        candidates => [ map $$_{id_str}, @$recent ],
    });

    $self->bot_says($channel, 'Which tweet?');
    for ( 1..@$recent ) {
        $self->bot_says($channel, "[$_] " . elide($recent->[$_ - 1]{text}, $self->truncate_to));
    }
};

sub _handle_favorite {
    my ($self, $channel, $index) = @_;

    $self->log->debug("[handle_favorite] $index");

    my @candidates = @{$self->stash->{candidates} || []};
    if ( $index =~ /^\d+$/ && 0 < $index && $index <= @candidates ) {
        if ( $self->twitter(create_favorite => { id => $candidates[$index - 1] }) ) {
            $self->bot_notice($channel, 'favorite added');
        }
        $self->clear_stash;
        return 1; # handled
    }
    return 0; # unhandled
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
        $self->bot_says($channel, sprintf "%s API calls remaining for the next %s (until %s), hourly limit is %s",
            $$r{remaining_hits},
            $time_remaning,
            $reset_time,
            $$r{hourly_limit},
        );
    }
};

=item retweet I<screen_name> [I<count>]

Re-tweet another user's status.  Specify the user by I<screen_name> and select from a
list of recent tweets. Optionally, specify the number of tweets to display for
selection with I<count> (Defaults to 3.)

=cut

event cmd_retweet => sub {
    my ( $self, $channel, $args ) = @_[OBJECT, ARG0, ARG1];

    unless ( defined $args ) {
        $self->bot_says($channel, 'usage: retweet nick [-N]');
        return;
    }

    my ( $nick, $count ) = split /\s+/, $args;

    $count ||= $self->favorites_count;

    my $recent = $self->twitter(user_timeline => { screen_name => $nick, count => $count }) || return;
    if ( @$recent == 0 ) {
        $self->bot_says($channel, "$nick has no recent tweets");
        return;
    }

    $self->stash({
        handler    => '_handle_retweet',
        candidates => [ map $$_{id_str}, @$recent ],
    });

    $self->bot_says($channel, 'Which tweet?');
    for ( 1..@$recent ) {
        $self->bot_says($channel, "[$_] " . elide($recent->[$_ - 1]{text}, $self->truncate_to));
    }
};

=item rt I<screen_name> [I<count>]

An alias for the C<retweet> command.

=cut

event cmd_rt => sub { shift->cmd_retweet(@_) };

sub _handle_retweet {
    my ($self, $channel, $index) = @_;

    my @candidates = @{$self->stash->{candidates} || []};
    if ( $index =~ /^\d+$/ && 0 < $index && $index <= @candidates ) {
        $self->twitter(retweet => { id => $candidates[$index - 1] });
        $self->clear_stash;
        return 1; # handled
    }
    return 0; # unhandled
};

=item reply I<screen_name> [I<-count>] I<message>

Reply to another user's status.  Specify the user by I<screen_name> and select
from a list of recent tweets. Optionally, specify the number of tweets to
display for selection with I<-count> (Defaults to 3.) Note that the count
parameter is prefixed with a dash.

=cut

event cmd_reply => sub {
    my ( $self, $channel, $args ) = @_[OBJECT, ARG0, ARG1];

    unless ( defined $args ) {
        $self->bot_says($channel, "usage: reply nick [-N] message-text");
        return;
    }

    my ( $nick, $count, $message ) = $args =~ /
        ^@?(\S+)        # nick; strip leading @ if there is one
        \s+
        (?:-(\d+)\s+)?  # optional count: -N
        (.*)            # the message
    /x;
    unless ( defined $nick && defined $message ) {
        $self->bot_says($channel, "usage: reply nick [-N] message-text");
        return;
    }


    $count ||= $self->favorites_count;

    my $recent = $self->twitter(user_timeline => { screen_name => $nick, count => $count }) || return;
    if ( @$recent == 0 ) {
        $self->bot_says($channel, "$nick has no recent tweets");
        return;
    }

    $self->stash({
        handler    => '_handle_reply',
        candidates => [ map $_->{id_str}, @$recent ],
        recipient  => $nick,
        message    => $message,
    });

    $self->bot_says($channel, 'Which tweet?');
    for ( 1..@$recent ) {
        $self->bot_says($channel, "[$_] " . elide($recent->[$_ - 1]{text}, $self->truncate_to));
    }
};

sub _handle_reply {
    my ($self, $channel, $index) = @_;

    my @candidates = @{$self->stash->{candidates} || []};
    if ( $index =~ /^\d+$/ && 0 < $index && $index <= @candidates ) {
        my $message = sprintf '@%s %s', @{$self->stash}{qw/recipient message/};
        if ( (my $n = length($message) - 140) > 0 ) {
            $self->bot_says($channel, "Message not sent; $n characters too long. Limit is 140 characters.");
        }
        else {
            $self->twitter(update => {
                status => $message,
                in_reply_to_status_id => $candidates[$index - 1],
            });
        }
        $self->clear_stash;
        return 1; # handled
    }
    return 0; # unhandled
};

=item report_spam

Report 1 or more screen names as spammers.

=cut

event cmd_report_spam => sub {
    my ( $self, $channel, $args ) = @_[OBJECT, ARG0, ARG1];

    unless ( $args ) {
        $self->bot_says($channel, "spam requires list of 1 or more spammers");
        return;
    }

    for my $spammer ( split /\s+/, $args ) {
        $self->yield(report_spam_helper => $spammer);
    }
};

event report_spam_helper => sub {
    my ( $self, $spammer ) = @_[OBJECT, ARG0];

    $self->twitter(report_spam => { screen_name => $spammer });
};

=item help

Display a simple help message

=cut

event cmd_help => sub {
    my ($self, $channel, $argstr)=@_[OBJECT, ARG0, ARG1];
    $self->bot_says($channel, "Available commands:");
    $self->bot_says($channel, join ' ' => sort qw/
        post follow unfollow block unblock whois notify favorite
        rate_limit_status retweet report_spam
    /);
    $self->bot_says($channel, '/msg nick for a direct message.')
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

=head1 CONTRIBUTORS

Adam Prime <adam.prime@utoronto.ca> (@adamprime)

=head1 LICENSE

Copyright (c) 2008 Marc Mims

You may distribute this code and/or modify it under the same terms as Perl itself.

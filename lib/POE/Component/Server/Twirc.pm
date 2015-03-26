package POE::Component::Server::Twirc;

use MooseX::POE;

use utf8;
use Log::Log4perl qw/:easy/;
use POE qw(Component::Server::IRC);
use Net::OAuth;
use Digest::SHA;
use String::Truncate elide => { marker => '…' };
use POE::Component::Server::Twirc::LogAppender;
use POE::Component::Server::Twirc::State;
use Encode qw/decode/;
use Try::Tiny;
use Scalar::Util qw/reftype weaken/;
use AnyEvent;
use AnyEvent::Twitter;
use AnyEvent::Twitter::Stream;
use HTML::Entities;
use Regexp::Common qw/URI/;
use JSON::MaybeXS;

with 'MooseX::Log::Log4perl';

=head1 NAME

POE::Component::Server::Twirc - Twitter/IRC gateway

=head1 SYNOPSIS

    use POE::Component::Server::Twirc;

    POE::Component::Server::Twirc->new;

    POE::Kernel->run;

=head1 DESCRIPTION

C<POE::Component::Server::Twirc> provides an IRC/Twitter gateway.  Twitter
friends are added to a channel and messages they post on twitter appear as
channel messages in IRC.  The IRC interface supports several Twitter features,
including posting status updates, following and un-following Twitter feeds,
enabling and disabling mobile device notifications or retweets, sending direct
messages, and querying information about specific Twitter users.

Friends who are also followers are given "voice" as a visual clue in IRC.

=head1 METHODS

=head2 new

Spawns a POE component encapsulating the Twitter/IRC gateway.

Arguments:

=over 4


=item irc_server_name

(Optional) The name of the IRC server. Defaults to C<twitter.irc>.

=cut

has irc_server_name => isa => 'Str', is => 'ro', default => 'twitter.irc';

=item irc_server_port

(Optional) The port number the IRC server binds to. Defaults to 6667.

=cut

has irc_server_port => isa => 'Int', is => 'ro', default => 6667;

=item irc_server_bindaddr

(Optional) The local address to bind to. Defaults to '127.0.0.1'.

=cut

# will be defaulted to INADDR_ANY by POE::Wheel::SocketFactory
has irc_server_bindaddr => isa => 'Str', is => 'ro', default => '127.0.0.1';

=item irc_mask

(Optional) The IRC user/host mask used to restrict connecting users.  Defaults to C<*@127.0.0.1>.

=cut

has irc_mask => isa => 'Str', is => 'ro', default => '*@127.0.0.1';


=item irc_password

(Optional) Password used to authenticate to the IRC server.

=cut

has irc_password => isa => 'Str', is => 'ro';


=item irc_botname

(Optional) The name of the channel operator bot.  Defaults to C<tweeter>.  Select a name
that does not conflict with friends, followers, or your own IRC nick.

=cut

has irc_botname => isa => 'Str', is => 'ro', default => 'tweeter';


=item irc_botircname

(Optional) Text to be used as the channel operator bot's IRC full name.

=cut

has irc_botircname => isa => 'Str', is => 'ro', default => 'Your friendly Twitter agent';


=item irc_channel

(Optional) The name of the channel to use.  Defaults to C<&twitter>.

=cut

has irc_channel => isa => 'Str', is => 'ro', default => '&twitter';

=item selection_count

(Optional) How many favorites candidates to display for selection. Defaults to 3.

=cut

has selection_count => isa => 'Int', is => 'ro', default => 3;

=item truncate_to

(Optional) When displaying tweets for selection, they will be truncated to this length.
Defaults to 60.

=cut

has truncate_to => isa => 'Int', is => 'ro', default => 60;


=item log_channel

(Optional) If specified, twirc will post log messages to this channel.

=cut

has log_channel => isa => 'Str', is => 'ro';

=item state_file

(Optional) File used to store state information between sessions, including last message read for
replies, direct messages, and timelines.

=cut

has state_file => isa => 'Str', is => 'ro';

=item plugins

(Optional) An array of plugin objects.

=cut

has plugins => isa => 'ArrayRef[Object]', is => 'ro', default => sub { [] };

=back


=cut

has irc_nickname => isa => 'Str', is => 'rw', init_arg => undef;

has ircd => (
    isa      => 'POE::Component::Server::IRC',
    is       => 'rw',
    weak_ref => 1,
    handles  => {
        add_auth          => 'add_auth',
        is_channel_member => 'state_is_chan_member',
        nick_exists       => 'state_nick_exists',
        post_ircd         => 'yield',
        user_route        => '_state_user_route',
    },
);

has _users_by_nick =>
    traits   => [qw/Hash/],
    isa      => 'HashRef[HashRef|Object]',
    is       => 'rw',
    init_arg => undef,
    lazy     => 1,
    default  => sub { +{ map { lc($$_{screen_name}) => $_ } shift->get_users } },
    handles  => {
        set_user         => 'set',
        get_user_by_nick => 'get',
        delete_user      => 'delete',
        user_nicks       => 'keys',
    };

around set_user => sub {
    my ( $orig, $self, $user ) = @_;

    $self->set_user_by_id($user->{id}, $user);
    $self->$orig(lc $user->{screen_name}, $user);
};

around get_user_by_nick => sub {
    my ( $orig, $self, $nick ) = @_;

    $self->$orig(lc $nick);
};

around delete_user => sub {
    my ( $orig, $self, $user ) = @_;

    $self->delete_user_by_id($user->{id});
    $self->$orig(lc $user->{screen_name});
};

has has_joined_channel => (
    init_arg => undef,
    is       => 'ro',
    traits   => [ qw/Bool/ ],
    default  => 0,
    handles  => {
        joined_channel => 'set',
        left_channel   => 'unset',
    },
);

has stash  => (
    init_arg => undef,
    isa => 'HashRef',
    traits => [ qw/Hash/ ],
    is => 'rw',
    predicate => 'has_stash',
    clearer => 'clear_stash',
    handles => {
        stashed_candidates     => [ get    => 'candidates' ],
        stashed_handler        => [ get    => 'handler'    ],
        stashed_message        => [ get    => 'message'    ],
        delete_stashed_handler => [ delete => 'handler'    ],
    },
);

around stashed_candidates => sub {
    my ( $orig, $self ) = @_;

    return @{ $self->$orig || [] };
};

has state => (
    isa      => 'POE::Component::Server::Twirc::State',
    is       => 'rw',
    lazy     => 1,
    default  => sub { POE::Component::Server::Twirc::State->new },
    handles  => [qw/
        access_token
        access_token_secret
        delete_user_by_id
        followers
        add_follower_id
        remove_follower_id
        is_follower_id
        followers_updated_at
        get_user_by_id
        get_users
        set_user_by_id
        store
    /],
);

has client_encoding => isa => 'Str', is  => 'rw', default => sub { 'utf-8' };

has reconnect_delay => is => 'rw', isa => 'Num', default => 0;
has twitter_stream_watcher => (
    is        => 'rw',
    clearer   => 'disconnect_twitter_stream',
    predicate => 'has_twitter_stream_watcher',
);

has authenticated_user => (
    is       => 'rw',
    isa      => 'HashRef',
    traits   => [ qw/Hash/ ],
    init_arg => undef,
    handles => {
        twitter_screen_name => [ get => 'screen_name' ],
        twitter_id          => [ get => 'id' ],
    },
);

has is_shutting_down => (
    is      => 'ro',
    traits  => [ qw/Bool/ ],
    default => 0,
    handles => {
        shutting_down => 'set',
    },
);

has twitter_rest_api => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        my $self = shift;

        AnyEvent::Twitter->new(
            $self->_twitter_auth,
            token            => $self->access_token,
            token_secret     => $self->access_token_secret,
        );
    },
    handles => {
        twitter_rest_api_request => 'request',
    },
);

sub to_json { JSON::MaybeXS->new->encode($_[1]) }
sub to_pretty_json { JSON::MaybeXS->new->pretty>encode($_[1]) }

# force build of users by nick hash early
sub BUILD { shift->_users_by_nick }

event get_authenticated_user => sub {
    my $self = $_[OBJECT];

    $self->twitter(verify_credentials => { include_entities => 1 },
        $_[SESSION]->callback('get_authenticated_user_response')
    );
};

event get_authenticated_user_response => sub {
    my $self = $_[OBJECT];
    my ( $r ) = @{ $_[ARG1] };

    if ( $r ) {
        $self->authenticated_user($r);
        if ( my $status = delete $$r{status} ) {
            $$status{user} = $r;
            $self->set_topic($self->formatted_status_text($status));
        }
        $self->yield('connect_twitter_stream');
    }
    else {
        FATAL("Failed to get authenticated user data from twitter (verify_credentials)");
        $self->yield('poco_shutdown');
    }
};

my %endpoint_for = (
    add_list_member    => [ post => 'lists/members/create'          ],
    create_block       => [ post => 'blocks/create'                 ],
    create_favorite    => [ post => 'favorites/create'              ],
    create_friend      => [ post => 'friendships/create'            ],
    destroy_block      => [ post => 'blocks/destroy'                ],
    destroy_friend     => [ post => 'friendships/destroy'           ],
    followers_ids      => [ get  => 'followers/ids'                 ],
    lookup_users       => [ get  => 'users/lookup'                  ],
    new_direct_message => [ post => 'direct_messages/new'           ],
    rate_limit_status  => [ get  => 'application/rate_limit_status' ],
    remove_list_member => [ post => 'lists/members/destroy'         ],
    report_spam        => [ post => 'users/report_spam'             ],
    retweet            => [ post => 'statuses/retweet/:id'          ],
    show_friendship    => [ get  => 'friendships/show'              ],
    show_user          => [ get  => 'users/show'                    ],
    update             => [ post => 'statuses/update'               ],
    update_friendship  => [ post => 'friendships/update'            ],
    user_timeline      => [ get  => 'statuses/user_timeline'        ],
    verify_credentials => [ get  => 'account/verify_credentials'    ],
);

sub twitter {
    my $cb = ref $_[-1] && reftype $_[-1] eq 'CODE' ? pop : sub {};
    my ( $self, $method, $args ) = @_;
    weaken $self;

    my ( $http_method, $endpoint ) = @{ $endpoint_for{$method} || [] }
        or return ERROR("no endopoint defined for $method");

    # Flatten array args into comma delimited strings
    for my $k ( keys %$args ) {
        $args->{$k} = join ',' => @{ $args->{$k} } if ref $args->{$k} eq ref [];
    }

    # handle path parameters
    $endpoint =~ s/:(\w+)$/delete $$args{$1}/e;

    DEBUG(qq/Twitter API call: $http_method $endpoint ${ \join ', ' => map { "$_ => '$$args{$_}'" } keys %$args }/);

    my $w; $w = $self->twitter_rest_api_request(
        method => $http_method,
        api    => $endpoint,
        params => $args,
        sub {
            my ( $header, $r, $reason, $http_response ) = @_;

            undef $w;
            if ( $r ) {
                $cb->($r);
            }
            else {
                $self->twitter_error(qq/$$header{Status}: $reason => ${ \join ', ' => map { "$$_{code}: $$_{message}" } @{ $http_response->{errors} } }/);
            }
        }
    );
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

    my $nick = $$user{screen_name};
    TRACE("add_user: $nick");

    # handle nick changes
    if ( my $current_user = $self->get_user_by_id($$user{id}) ) {
        $self->post_ircd(daemon_cmd_nick => $$current_user{screen_name}, $nick)
            if $nick ne $$current_user{screen_name};
    }

    $$user{FRESH} = time;
    $self->set_user($user);

    unless ( $self->nick_exists($nick) ) {
        $self->post_ircd(add_spoofed_nick => { nick => $nick, ircname => $$user{name} });
    }
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

sub max_reconnect_delay    () { 600 } # ten minutes
sub twitter_stream_timeout () {  65 } # should get activity every 30 seconds
sub friends_stale_after    () { 7*24*3600 } # 1 week

sub is_user_stale {
    my ( $self, $user ) = @_;

    return time - $user->{FRESH} > $self->friends_stale_after;
}

sub followers_stale_after () { 24*3600 } # 1 day
sub are_followers_stale {
    my $self = shift;

    return time - $self->followers_updated_at > $self->followers_stale_after;
}

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

    # When the status is a retweet from verify_credentials, it doesn't have a user element
    my $orig_author = $$s{user}{screen_name} || $$status{entities}{user_mentions}[0]{screen_name};
    $text = "RT \@$orig_author: $text" if $is_retweet;

    return $text;
}

event connect_twitter_stream => sub {
    weaken(my $self = $_[OBJECT]);

    TRACE('connect_twitter_stream');

    my $w = AnyEvent::Twitter::Stream->new(
        $self->_twitter_auth,
        token        => $self->access_token,
        token_secret => $self->access_token_secret,
        method       => 'userstream',
        timeout      => $self->twitter_stream_timeout,
        on_connect   => sub {
            INFO('Connected to Twitter');
            $self->bot_notice($self->irc_channel, "Twitter stream connected");
            $self->reconnect_delay(0);
        },
        on_eof       => sub {
            $self->disconnect_twitter_stream;
            TRACE("on_eof");
            $self->bot_notice($self->irc_channel, "Twitter stream disconnected");
            $self->yield('connect_twitter_stream') unless $self->is_shutting_down;
        },
        on_error   => sub {
            my $e = shift;

            ERROR("on_error: $e");
            $self->bot_notice($self->irc_channel, "Twitter stream error: $e");
            if ( $e =~ /^420:/ ) {
                FATAL("excessive login rate; shutting down");
                $self->yield('poco_shutdown');
                return;
            }

            $self->disconnect_twitter_stream;

            # progressively backoff on reconnection attepts to max_reconnect_delay
            if ( my $delay = $self->reconnect_delay ) {
                DEBUG("delaying $delay seconds before reconnecting");
            }
            my $t; $t = AE::timer $self->reconnect_delay, 0, sub {
                undef $t;
                my $next_delay = $self->reconnect_delay * 2 || 1;
                $next_delay = $self->max_reconnect_delay if $next_delay > $self->max_reconnect_delay;
                $self->reconnect_delay($next_delay);
                $self->yield('connect_twitter_stream');
            };
        },
        on_keepalive   => sub {
            TRACE("on_keepalive");
        },
        on_friends   => sub {
            TRACE("on_friends: ", $self->to_json(@_));
            $self->yield(friends_ids => shift);
        },
        on_event     => sub {
            my $msg = shift;

            TRACE("on_event: $$msg{event}");
            $self->yield(on_event => $msg);
        },
        on_tweet     => sub {
            my $msg = shift;

            TRACE("on_tweet");

            return unless $self->has_joined_channel;

            if ( exists $$msg{sender} ) {
                DEBUG('received old style direct_message');
                $self->yield(on_direct_message => $msg);
            }
            elsif ( exists $$msg{text} ) {
                $self->yield(on_tweet => $msg);
            }
            elsif ( exists $$msg{direct_message} ) {
                $self->yield(on_direct_message => $$msg{direct_message});
            }
            elsif ( exists $$msg{limit} ) {
                WARN("track limit: $$msg{limit}{track}");
                $self->bot_notice($self->irc_channel,
                    "Track limit received - $$msg{limit}{track} statuses missed.");
            }
            elsif ( exists $$msg{scrub_geo} ) {
                # $$msg{scrub_geo} = {"user_id":14090452,"user_id_str":"14090452","up_to_status_id":23260136625,"up_to_status_id_str":"23260136625"}
                my $e = $$msg{scrub_geo};
                INFO("scrub_geo: user_id=$$e{user_id}, up_to_status_id=$$e{up_to_status_id}");
            }
            else {
                ERROR("unexpected message: ", $self->to_pretty_json($msg));
                $self->bot_notice($self->irc_channel, "Unexpected twitter packet, see the log for details");
            }
        },
        on_delete    => sub {
            TRACE("on_delete");
        },
    );

    $self->twitter_stream_watcher($w);
};

sub START {
    weaken(my $self = $_[OBJECT]);

    $self->ircd(
        POE::Component::Server::IRC->spawn(
            config => {
                servername => $self->irc_server_name,
                nicklen    => 15,
                network    => 'SimpleNET'
            },
            inline_states => {
                _stop  => sub { TRACE('[ircd:stop]') },
            },
        )
    );

    # register ircd to receive events
    $self->post_ircd('register' );
    $self->add_auth(
        mask     => $self->irc_mask,
        password => $self->irc_password,
        no_tilde => 1,
    );
    $self->post_ircd('add_listener', port     => $self->irc_server_port,
                                     bindaddr => $self->irc_server_bindaddr);

    # add super user
    $self->post_ircd(add_spoofed_nick => {
        nick    => $self->irc_botname,
        ircname => $self->irc_botircname,
    });
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

    POE::Kernel->sig(TERM => 'poco_shutdown');
    POE::Kernel->sig(INT  => 'poco_shutdown');

    $self->yield('get_authenticated_user');

    return $self;
}

# Without detaching the ircd child session, the application will not
# shut down.  Bug in PoCo::Server::IRC?
event _child => sub {
    my ($self, $kernel, $event, $child) = @_[OBJECT, KERNEL, ARG0, ARG1];

    TRACE("[_child] $event $child");
    $kernel->detach_child($child) if $event eq 'create';
};

event poco_shutdown => sub {
    my ($self) = @_;

    TRACE("[poco_shutdown]");
    $self->shutting_down;
    $self->disconnect_twitter_stream;
    $_[KERNEL]->alarm_remove_all();
    $self->post_ircd('unregister');
    $self->post_ircd('shutdown');
    if ( $self->state_file ) {
        try { $self->store($self->state_file) }
        catch {
            s/ at .*//s;
            ERROR($_);
            $self->bot_notice($self->irc_channel, "Error storing state file: $_");
        };
    }

    # TODO: Why does twirc often fail to shut down?
    # This is surely the WRONG thing to do, but hit the big red kill switch.
    exit 0;
};

########################################################################
# IRC events
########################################################################

event ircd_daemon_nick => sub {
    my ($self, $sender, $nick) = @_[OBJECT, SENDER, ARG0];

    TRACE("[ircd_daemon_nick] $nick");

    # if it's a nick change, we only get ARG0 and ARG1
    return unless defined $_[ARG2];
    return if $self->user_route($nick) eq 'spoofed';

    $self->irc_nickname($nick);

    # Abuse!  Calling the private implementation of ircd to force-join the connecting
    # user to the twitter channel. ircd set's it's heap to $self: see ircd's perldoc.
    $sender->get_heap->_daemon_cmd_join($nick, $self->irc_channel);

    # Give the user half ops (just a visual cue)
    $self->post_ircd(daemon_cmd_mode => $self->irc_botname, $self->irc_channel, '+h', $nick);
};

event ircd_daemon_join => sub {
    my($self, $sender, $user, $ch) = @_[OBJECT, SENDER, ARG0, ARG1];

    TRACE("[ircd_daemon_join] $user, $ch");
    return unless my($nick) = $user =~ /^([^!]+)!/;
    return if $self->user_route($nick) eq 'spoofed';

    if ( $ch eq $self->irc_channel ) {
        $self->joined_channel;
        TRACE("    joined!");
        return;
    }
    elsif ( $self->log_channel && $ch eq $self->log_channel ) {
        my $appender = Log::Log4perl->appender_by_name('twirc-logger');
        $appender->dump_history;
    }
    else {
        TRACE("    ** part **");
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

    $self->left_channel if $ch eq $self->irc_channel && $nick eq $self->irc_nickname;
};

event ircd_daemon_quit => sub {
    my($self, $user) = @_[OBJECT, ARG0];

    TRACE("[ircd_daemon_quit]");
    return unless my($nick) = $user =~ /^([^!]+)!/;
    return unless $nick eq $self->irc_nickname;

    $self->left_channel;
    $self->yield('poco_shutdown');
};

event ircd_daemon_public => sub {
    my ($self, $user, $channel, $text) = @_[OBJECT, ARG0, ARG1, ARG2];

    return unless $channel eq $self->irc_channel;

    $text = decode($self->client_encoding, $text);

    $text =~ s/\s+$//;

    my $nick = ( $user =~ m/^(.*)!/)[0];

    TRACE("[ircd_daemon_public] $nick: $text");
    return unless $nick eq $self->irc_nickname;

    # give any command handler a shot
    if ( $self->has_stash ) {
        DEBUG("stash exists...");
        my $handler = $self->delete_stashed_handler;
        if ( $handler ) {
            return if $self->call($handler, $channel, $text); # handled
            $self->clear_stash;
        }
        else {
            ERROR("stash exists with no handler");
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

    $self->twitter(new_direct_message => { screen_name => $target_nick, text => $text });
};

event friend_join => sub {
    my ( $self, $friend ) = @_[OBJECT, ARG0];

    my $nick = $$friend{screen_name};
    TRACE("friend_join: $nick");

    $self->post_ircd(add_spoofed_nick => { nick => $nick, ircname => $$friend{name} })
        unless $self->nick_exists($nick);

    $self->post_ircd(daemon_cmd_join => $nick, $self->irc_channel);
    if ( $self->is_follower_id($$friend{id}) ) {
        $self->post_ircd(daemon_cmd_mode => $self->irc_botname, $self->irc_channel, '+v', $nick);
    }
};

event lookup_friends => sub {
    my ( $self, $session, $ids ) = @_[OBJECT, SESSION, ARG0];

    return unless @$ids;

    $self->twitter(lookup_users => { user_id => $ids },
        $session->callback('lookup_friends_response')
    );
};

event lookup_friends_response => sub {
    my $self = $_[OBJECT];
    my ( $r ) = @{ $_[ARG1] };

    for my $friend ( @{$r || []} ) {
        delete $friend->{status};
        $self->add_user($friend);
        $self->yield(friend_join => $friend);
    }
    $self->store($self->state_file) if $self->state_file;
};

event get_followers_ids => sub {
    weaken(my $self = $_[OBJECT]);

    $self->twitter(followers_ids => { cursor => -1 },
        $_[SESSION]->callback(get_followers_ids_response => {})
    );
};

event get_followers_ids_response => sub {
    weaken(my $self = $_[OBJECT]);
    my ( $followers ) = @{ $_[ARG0] };
    my ( $r )         = @{ $_[ARG1] };

    $$followers{$_} = undef for @{$$r{ids}};

    if ( my $cursor = $r->{next_cursor} ) {
        $self->twitter(follower_ids => { cursor => $cursor },
            $_[SESSION]->callback(get_followers_ids_response => $followers)
        );
        return;
    }
    if ( %$followers ) {
        $self->followers($followers);
        $self->followers_updated_at(time);

        $self->yield('set_voice');
    }
};

event set_voice => sub {
    my  $self = $_[OBJECT];

    for my $user ( $self->get_users ) {
        my $mode = $self->is_follower_id($$user{id}) ? '+v' : '-v';

        $self->post_ircd(daemon_cmd_mode => $self->irc_botname, $self->irc_channel, $mode,
            $$user{screen_name});
    }
};

########################################################################
# Twitter events
########################################################################

event friends_ids => sub {
    my ( $self, $kernel, $friends_ids ) = @_[OBJECT, KERNEL, ARG0];

    my $buffer = [];
    for my $id ( @$friends_ids ) {
        my $friend = $self->get_user_by_id($id);
        if ( !$friend || $self->is_user_stale($friend) ) {
            push @$buffer, $id;
            if ( @$buffer == 100 ) {
                $self->yield(lookup_friends => [ @$buffer ]);
                $buffer = [];
                $kernel->run_one_timeslice;
            }
        }
        else {
            $self->yield(friend_join => $friend);
        }
    }

    $self->yield(lookup_friends => $buffer);
    $self->yield('get_followers_ids');
};

event on_tweet => sub {
    my ( $self, $status ) = @_[OBJECT, ARG0];

    # add or freshen user
    $self->add_user($$status{user});

    my $nick = $$status{user}{screen_name};
    my $text = $self->formatted_status_text($status);
    if ( $nick eq $self->irc_nickname ) {
        $self->set_topic($text);
    }

    unless ( $self->is_channel_member($nick, $self->irc_channel) ) {
        $self->post_ircd(daemon_cmd_join => $nick, $self->irc_channel);
    }

    TRACE("on_tweet: <$nick> $text");
    $self->post_ircd(daemon_cmd_privmsg => $nick, $self->irc_channel, $_) for split /[\r\n]+/, $text;
};

event on_event => sub {
    my ( $self, $msg ) = @_[OBJECT, ARG0];

    ### Potential events:
    #
    ## implemented:
    # retweet
    # follow unfollow
    # block unblock
    # favorite unfavorite
    #
    ## unimplemented:
    # user_update
    # list_created list_updated list_destroyed
    # list_member_added list_member_removed
    # list_user_subscribed list_user_unsubscribed

    my $method = "on_event_$$msg{event}";
    return $self->$method($msg) if $self->can($method);

    $self->bot_notice($self->irc_channel, "Unhandled Twitter stream event: $$msg{event}");
    DEBUG("unhandled event", $self->to_pretty_json($msg));
};

sub on_event_follow {
    my ( $self, $event ) = @_;

    if ( my $source = $$event{source} ) {
        my $target = $$event{target} or return;

        # new friend
        if ( $$source{id} eq $self->twitter_id ) {
            $self->yield(friend_join => $target);
            $self->bot_notice($self->irc_channel, qq/Now following $$target{screen_name}./);
        }

        # new follower
        elsif ( $$target{id} eq $self->twitter_id ) {
            $self->bot_notice($self->irc_channel, qq`\@$$source{screen_name} "$$source{name}" `
                    . qq`is following you https://twitter.com/$$source{screen_name}`);
            $self->add_follower_id($$source{id});
        }
    }
}

sub on_event_unfollow {
    my ( $self, $event ) = @_;

    my $screen_name = $event->{target}{screen_name};
    if( my $user = $self->get_user_by_nick($screen_name) ) {
        $self->delete_user($user);
    }
    $self->post_ircd(daemon_cmd_part => $screen_name, $self->irc_channel);
    $self->post_ircd(del_spooked_nick => $screen_name);
    $self->bot_notice($self->irc_channel, qq/No longer following $screen_name./);
}

sub on_event_favorite   { shift->_favorite_or_retweet(favorited   => @_) }
sub on_event_unfavorite { shift->_favorite_or_retweet(unfavorited => @_) }
sub on_event_retweet    { shift->_favorite_or_retweet(retweeted   => @_) }
sub _favorite_or_retweet {
    my ( $self, $verb, $event ) = @_;

    my $status = $$event{target_object};
    my $who  = $$event{source}{id} eq $self->twitter_id ? 'You'  : $$event{source}{screen_name};
    my $whom = $$event{target}{id} eq $self->twitter_id ? 'your' : "$$event{target}{screen_name}'s";
    my $link = "https://twitter.com/$$status{user}{screen_name}/status/$$status{id}";
    my $text = $self->formatted_status_text($status);

    $self->bot_notice($self->irc_channel,
        elide(qq/$who $verb $whom "$text"/, 80, { marker => '…"' }) . " [$link]");
}

# No need to alert, here. We also get an on_event_favorite for the same tweet
sub on_event_favorited_retweet {}

sub on_event_block {
    my ( $self, $event ) = @_;

    my $target = $$event{target};
    if ( $self->get_user_by_id($$target{id}) ) {
        $self->post_ircd(daemon_cmd_mode =>
            $self->irc_botname, $self->irc_channel, '-v', $$target{screen_name});
        $self->remove_follower_id($$target{id});
    }
    $self->bot_notice($self->irc_channel, qq/You blocked $$target{screen_name}./);
}

sub on_event_unblock {
    my ( $self, $event ) = @_;

    my $target = $$event{target};
    if ( $self->get_user_by_id($$target{id}) ) {
        $self->post_ircd(daemon_cmd_mode =>
            $self->irc_botname, $self->irc_channel, '+v', $$target{screen_name});
    }
    $self->bot_notice($self->irc_channel, qq/You unblocked $$target{screen_name}./);
}

sub on_event_list_member_added   { shift->_list_add_or_remove(qw/added to/,     @_) }
sub on_event_list_member_removed { shift->_list_add_or_remove(qw/removed from/, @_) }
sub _list_add_or_remove {
    my ( $self, $verb, $preposition, $event ) = @_;

    my $list = $$event{target_object};
    my $who  = $$event{source}{id} eq $self->twitter_id ? 'You' : $$event{source}{screen_name};
    my $whom = $$event{target}{id} eq $self->twitter_id ? 'you' : $$event{target}{screen_name};
    my $link = "https://twitter.com$$list{uri}";

    $self->bot_notice($self->irc_channel, "$who $verb $whom $preposition list [$$list{name}]($link)");
}

event on_direct_message => sub {
    my ( $self, $msg ) = @_[OBJECT, ARG0];

    if ( $$msg{recipient_screen_name} ne $self->twitter_screen_name ) {
        INFO('direct message sent to @', $$msg{recipient_screen_name});
        return;
    }

    my $nick = $$msg{sender_screen_name};
    my $sender = $$msg{sender};

    unless ( $self->nick_exists($nick) ) {
        # This shouldn't happen - twitter only allows direct messages to followers, so
        # we *should* already have $nick on board.
        $self->post_ircd(add_spoofed_nick => { nick => $nick, ircname => $$sender{name} });
        $self->add_user($sender);
    }

    my $text = $self->formatted_status_text($msg);
    $self->post_ircd(daemon_cmd_privmsg => $nick, $self->irc_nickname, $_)
            for split /\r?\n/, $text;
};

sub on_event_retweeted_retweet {
    my ( $self, $msg ) = @_;

    my $screen_name = $msg->{source}{screen_name};
    my $text = $self->formatted_status_text($msg->{target_object});

    $self->bot_notice($self->irc_channel, "$screen_name retweeted your retweet: $text");
}

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

    TRACE("[cmd_post_status]");

    return if $self->status_text_too_long($channel, $text);

    $self->twitter(update => { status => $text },
        $_[SESSION]->callback('cmd_post_response')
    );
};

event cmd_post_response => sub {
    my $self = $_[OBJECT];
    my ( $r ) = @{ $_[ARG1] };

    TRACE("    update returned $r->{id}") if $r;
};

sub status_text_too_long {
    my ( $self, $channel, $text ) = @_;

    if ( (my $n = $self->_calc_text_length($text) - 140) > 0 ) {
        $self->bot_says($channel, "$n characters too long.");
        return $n;
    }

    return;
}

sub _calc_text_length {
    my ( $self, $text ) = @_;

    my $http_urls  = $text =~ s/$RE{URI}{HTTP}//g;
    my $https_urls = $text =~ s/$RE{URI}{HTTP}{-scheme => 'https'}//g;

    return length($text) + $http_urls * 20 + $https_urls * 21;
}

=item follow I<id>

Follow a new Twitter user, I<id>.  In Twitter parlance, this creates a friendship.

=cut

event cmd_follow => sub {
    my ($self, $channel, $id) = @_[OBJECT, ARG0, ARG1];

    if ( $id !~ /^\w+$/ ) {
        $self->bot_says($channel, qq/"$id" doesn't look like a user ID to me./);
        return;
    }

    $self->twitter(create_friend => { screen_name => $id });
};

=item unfollow I<id>

Stop following Twitter user I<id>.  In Twitter, parlance, this destroys a
friendship.

=cut

event cmd_unfollow => sub {
    my ($self, $channel, $id) = @_[OBJECT, ARG0, ARG1];

    my $user = $self->get_user_by_nick($id);
    unless ( $user ) {
        $self->bot_says($channel, qq/You don't appear to be following $id./);
        return;
    }

    $self->twitter(destroy_friend => { screen_name => $id });
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

    $self->twitter(create_block => { screen_name => $id });
};

=item unblock I<id>

Stop blocking Twitter user I<id>.

=cut

event cmd_unblock => sub {
    my ( $self, $channel, $id ) = @_[OBJECT, ARG0, ARG1];

    if ( $id !~ /^\w+$/ ) {
        $self->bot_says($self->irc_channel, qq/"$id" doesn't look like a Twitter screen name to me./);
        return;
    }

    $self->twitter(destroy_block => { screen_name => $id});
};

=item whois I<id>

Displays information about Twitter user I<id>, including name, location, and
description.

=cut

event cmd_whois => sub {
    my ($self, $channel, $nick) = @_[OBJECT, ARG0, ARG1];

    TRACE("[cmd_whois] $nick");


    if ( my $user = $self->get_user_by_nick($nick) ) {
        $self->yield('cmd_whois_response' => [ $channel, $nick ], [ $user ]);
    }
    else {
        TRACE("     $nick not in users; fetching");
        $self->twitter(show_user => { screen_name => $nick },
            $_[SESSION]->callback(cmd_whois_response => $channel, $nick)
        );
    }
};

event cmd_whois_response => sub {
    my $self = $_[OBJECT];
    my ( $channel, $nick ) = @{ $_[ARG0] };
    my ( $user ) = @{ $_[ARG1] };

    if ( $user ) {
        $self->bot_says($channel, sprintf '%s [%s]: %s, %s',
            @{$user}{qw/screen_name id name/},
            (map decode_entities(defined $_ ? $_ : ''),
                @{$user}{qw/location description/}),
            $$user{url}
        );
    }
    else {
        $self->bot_says($channel, "I don't know $nick.");
    }
};

=item notify I<on|off> I<screen_name ...>

Turns mobile device notifications on or off for the list of I<screen_name>s.

=cut

event cmd_notify => sub {
    my $self = $_[OBJECT];
    $self->call(_update_fship => 'device', @_[ARG0, ARG1]);
};

=item retweets I<on|off> I<screen_name ...>

Turns retweet display on your timeline on or off for the list of
I<screen_name>s.

=cut

event cmd_retweets => sub {
    my $self = $_[OBJECT];
    $self->call(_update_fship => 'retweets', @_[ARG0, ARG1]);
};

# Call update_friendships
# All settings updated at once so existing must be preserved
event _update_fship => sub {
    my ($self, $command, $channel, $argstr) = @_[OBJECT, ARG0..ARG2];

    my @nicks = split /\s+/, $argstr;
    my $onoff = shift @nicks;

    unless ( $onoff && $onoff =~ /^on$|^off$/ ) {
        $self->bot_says($channel, "Usage: $command on|off nick[ nick [...]]");
        return;
    }

    my $setting = $onoff eq 'on' ? 1 : 0;
    for my $nick ( @nicks ) {
        $self->twitter(show_friendship => { target_screen_name => $nick },
            $_[SESSION]->callback( _update_fship_response =>
                $command, $channel, $nick, $setting
            )
        );
    }
};

event _update_fship_response => sub {
    my $self = $_[OBJECT];
    my ( $r ) = @{ $_[ARG1] } or return;
    my ( $command, $channel, $nick, $setting ) = @{ $_[ARG0] };

    my $source = $r->{relationship}{source};
    # Pull out existing settings
    # Quoted values to get 0/1 vs weird JSON:: things that break the API
    my %current_value = (
        device   => "$source->{notifications_enabled}",
        retweets => "$source->{want_retweets}",
    );

    # Skip unnecessary updates
    if ( $current_value{$command} == $setting ) {
        $self->bot_says($channel, "No need to update $nick");
        return;
    }

    # Update
    $self->twitter(update_friendship => {
        screen_name => $nick,
        # current values as default
        %current_value,
        # override with new value
        $command => $setting
    });
};

=item favorite I<screen_name> [I<count>]

Mark a tweet as a favorite.  Specify the user by I<screen_name> and select from a
list of recent tweets. Optionally, specify the number of tweets to display for
selection with I<count> (Defaults to 3.)

=cut

event cmd_favorite => sub {
    my ($self, $channel, $args) = @_[OBJECT, ARG0, ARG1];

    my ($nick, $count) = split /\s+/, $args;
    $count ||= $self->selection_count;

    TRACE("[cmd_favorite] $nick");

    $self->twitter(user_timeline => { screen_name => $nick, count => $count },
        $_[SESSION]->callback(cmd_favorite_response => $channel, $nick)
    );
};

event cmd_favorite_response => sub {
    my $self = $_[OBJECT];
    my ( $recent ) = @{ $_[ARG1] } or return;
    my ( $channel, $nick ) = @{ $_[ARG0] };

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
        $self->bot_says($channel, "[$_] " .
            elide(
                $self->formatted_status_text($recent->[$_ - 1]),
                $self->truncate_to
            )
        );
    }
};

event _handle_favorite => sub {
    my ( $self, $channel, $index ) = @_[OBJECT, ARG0, ARG1];

    TRACE("[handle_favorite] $index");

    my @candidates = $self->stashed_candidates;
    if ( $index =~ /^\d+$/ && 0 < $index && $index <= @candidates ) {
        $self->twitter(create_favorite => { id => $candidates[$index - 1] });
        return 1; # handled
    }
    return 0; # unhandled
};

=item rate_limit_status

Displays the remaining number of API requests available in the current hour.

=cut

event cmd_rate_limit_status => sub {
    my ($self, $channel) = @_[OBJECT, ARG0];

    $self->twitter('rate_limit_status', {},
        $_[SESSION]->callback(cmd_rate_limit_status_response => $channel)
    );
};

event cmd_rate_limit_status_response => sub {
    my $self = $_[OBJECT];
    my ( $r ) = @{ $_[ARG1] } or return;
    my ( $channel ) = @{ $_[ARG0] };

    my $reset_time = sprintf "%02d:%02d:%02d", (localtime $r->{reset_time_in_seconds})[2,1,0];
    my $seconds_remaining = $r->{reset_time_in_seconds} - time;
    my $time_remaining = sprintf "%d:%02d", int($seconds_remaining / 60), $seconds_remaining % 60;
    $self->bot_says($channel, sprintf "%s API calls remaining for the next %s (until %s), hourly limit is %s",
        $$r{remaining_hits},
        $time_remaining,
        $reset_time,
        $$r{hourly_limit},
    );
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

    $count ||= $self->selection_count;

    $self->twitter(user_timeline => { screen_name => $nick, count => $count },
        $_[SESSION]->callback(cmd_retweet_response => $channel, $nick)
    );
};

event cmd_retweet_response => sub {
    my $self = $_[OBJECT];
    my ( $recent ) = @{ $_[ARG1] } or return;
    my ( $channel, $nick ) = @{ $_[ARG0] };

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
        $self->bot_says($channel, "[$_] " .
            elide(
                $self->formatted_status_text($recent->[$_ - 1]),
                $self->truncate_to
            )
        );
    }
};

=item rt I<screen_name> [I<count>]

An alias for the C<retweet> command.

=cut

event cmd_rt => sub { shift->cmd_retweet(@_) };

event _handle_retweet => sub {
    my ( $self, $channel, $index ) = @_[OBJECT, ARG0, ARG1];

    my @candidates = $self->stashed_candidates;
    if ( $index =~ /^\d+$/ && 0 < $index && $index <= @candidates ) {
        $self->twitter(retweet => { id => $candidates[$index - 1] });
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

    $message = "\@$nick $message";
    return if $self->status_text_too_long($channel, $message);

    $count ||= $self->selection_count;

    $self->twitter(user_timeline => { screen_name => $nick, count => $count },
        $_[SESSION]->callback(cmd_reply_response => $channel, $nick, $message)
    );
};

event cmd_reply_response => sub {
    my $self = $_[OBJECT];
    my ( $recent ) = @{ $_[ARG1] } or return;
    my ( $channel, $nick, $message ) = @{ $_[ARG0] };

    if ( @$recent == 0 ) {
        $self->bot_says($channel, "$nick has no recent tweets");
        return;
    }

    $self->stash({
        handler    => '_handle_reply',
        candidates => [ map $_->{id_str}, @$recent ],
        message    => $message,
    });

    $self->bot_says($channel, 'Which tweet?');
    for ( 1..@$recent ) {
        $self->bot_says($channel, "[$_] " .
            elide(
                $self->formatted_status_text($recent->[$_ - 1]),
                $self->truncate_to
            )
        );
    }
};

event _handle_reply => sub {
    my ( $self, $channel, $index ) = @_[OBJECT, ARG0, ARG1];

    my @candidates = $self->stashed_candidates;
    if ( $index =~ /^\d+$/ && 0 < $index && $index <= @candidates ) {
        $self->twitter(update => {
            status                => $self->stashed_message,
            in_reply_to_status_id => $candidates[$index - 1],
        });
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

=item add I<screen_name> to I<list-slug>

Add a user to one of your lists.

=cut

event cmd_add => sub { $_[OBJECT]->_add_remove_list_member(qw/add to/, @_[ARG0, ARG1]) };

sub _add_remove_list_member {
    my ( $self, $verb, $preposition, $channel, $args ) = @_;

    my ( $nick, $slug ) = ($args || '') =~ /
        ^@?(\w+)        # nick; strip leading @ if there is one
        \s+$preposition\s+
        ([-\w]+)        # the list-slug
        \s*$
    /x;

    unless ( defined $nick ) {
        $self->bot_says($channel, "usage: $verb <nick> $preposition <list-slug>");
        return;
    }

    $self->twitter($verb . '_list_member' => {
        owner_id    => $self->twitter_id,
        slug        => $slug,
        screen_name => $nick,
    });
};

=item remove I<screen_name> from I<list-slug>

Add a user to one of your lists.

=cut

event cmd_remove => sub { $_[OBJECT]->_add_remove_list_member(qw/remove from/, @_[ARG0, ARG1]) };

=item help

Display a simple help message

=cut

event cmd_help => sub {
    my ($self, $channel, $argstr)=@_[OBJECT, ARG0, ARG1];
    $self->bot_says($channel, "Available commands:");
    $self->bot_says($channel, join ' ' => sort qw/
        post follow unfollow block unblock whois notify retweets favorite
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
Peter Roberts <me+dev@peter-r.co.uk>

=head1 LICENSE

Copyright (c) 2008 Marc Mims

You may distribute this code and/or modify it under the same terms as Perl itself.

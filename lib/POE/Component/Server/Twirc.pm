package POE::Component::Server::Twirc;
use MooseX::POE;

use LWP::UserAgent::POE;
use POE qw(Component::Server::IRC);
use Net::Twitter;
use String::Truncate elide => { marker => '…' };
use POE::Component::Server::Twirc::LogAppender;
use POE::Component::Server::Twirc::State;
use Encode qw/decode/;
use Try::Tiny;
use Scalar::Util qw/reftype/;
use AnyEvent;
use AnyEvent::Twitter::Stream;
use HTML::Entities;
use Regexp::Common qw/URI/;

with 'MooseX::Log::Log4perl';

our $VERSION = '0.13';

=head1 NAME

POE::Component::Server::Twirc - Twitter/IRC gateway

=head1 SYNOPSIS

    use POE::Component::Server::Twirc;

    POE::Component::Server::Twirc->new;

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


=item twitter_args

(Optional) A hashref of extra arguments to pass to C<< Net::Twitter->new >>.

=cut

has twitter_args => isa => 'HashRef', is => 'ro', default => sub { {} };

=item extra_net_twitter_traits

(Optional) Additional traits used to construct the Net::Twitter instance.

=cut

has extra_net_twitter_traits => is => 'ro', default => sub { [] };

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

has _twitter => is => 'rw', isa => 'Object', lazy => 1, default => sub {
    my $self = shift;

    Net::Twitter->new(
        $self->_net_twitter_opts,
        access_token        => $self->state->access_token,
        access_token_secret => $self->state->access_token_secret,
    );
};

has ircd => isa => 'POE::Component::Server::IRC', is => 'rw', weak_ref => 1;

has _users_by_nick =>
    traits   => [qw/Hash/],
    isa      => 'HashRef[HashRef|Object]',
    is       => 'rw',
    init_arg => undef,
    lazy     => 1,
    default  => sub { +{ map { lc($$_{screen_name}) => $_ } shift->get_users } },
    handles  => {
        set_user_by_nick    => 'set',
        get_user_by_nick    => 'get',
        delete_user_by_nick => 'delete',
        user_nicks          => 'keys',
    };

has joined => init_arg => undef, isa => 'Bool', is => 'rw', default => 0;
has stash  => init_arg => undef, isa => 'HashRef', is => 'rw', predicate => 'has_stash', clearer => 'clear_stash';

has state =>
    isa      => 'POE::Component::Server::Twirc::State',
    is       => 'rw',
    lazy     => 1,
    handles  => [qw/set_user_by_id get_user_by_id delete_user_by_id get_users/],
    default  => sub { POE::Component::Server::Twirc::State->new };

has client_encoding => isa => 'Str', is  => 'rw', default => sub { 'utf-8' };

has reconnect_delay => is => 'rw', isa => 'Num', default => 0;
has twitter_stream_watcher => is => 'rw', clearer => 'disconnect_twitter_stream',
        predicate => 'has_twitter_stream_watcher';

has authenticated_user => is => 'rw', isa => 'HashRef', init_arg => undef;

# force build of users by nick hash early
sub BUILD { shift->_users_by_nick }

sub get_authenticated_user {
    my $self = shift;

    if ( my $r = $self->twitter(verify_credentials => { include_entities => 1 }) ) {
        $self->authenticated_user($r);
        if ( my $status = delete $$r{status} ) {
            $$status{user} = $r;
            $self->set_topic($self->formatted_status_text($status));
        }
    }
    else {
        $self->log->fatal("Failed to get authenticated user data from twitter (verify_credentials)");
        $self->call('poco_shutdown');
    }
};

sub twitter {
    my ($self, $method, @args) = @_;

    my $r = try { $self->_twitter->$method(@args) }
    catch {
        $self->log->error("twitter errer: $_");
        if ( blessed $_ && $_->can('code') && $_->code == 502 ) {
            $_ = 'Fail Whale';
        }
        s/ at .* line \d+//;
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

    my $nick = $$user{screen_name};
    $self->log->trace("add_user: $nick");

    # handle nick changes
    if ( my $current_user = $self->get_user_by_id($$user{id}) ) {
        $self->post_ircd(daemon_cmd_nick => $$current_user{screen_name}, $nick)
            if $nick ne $$current_user{screen_name};
    }

    $$user{FRESH} = time;
    $self->set_user_by_id($user->{id}, $user);
    $self->set_user_by_nick(lc($user->{screen_name}), $user);

    unless ( $self->ircd->state_nick_exists($nick) ) {
        $self->post_ircd(add_spoofed_nick => { nick => $nick, ircname => $$user{name} });
    }
}

sub delete_user {
    my ($self, $user) = @_;

    $self->delete_user_by_id($user->{id});
    $self->delete_user_by_nick(lc($user->{screen_name}));
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
        traits               => [qw/API::REST OAuth RetryOnError/],
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

    return time - $self->state->followers_updated_at > $self->followers_stale_after;
}

sub add_follower_id {
    my ( $self, $id ) = @_;

    $self->state->followers->{$id} = undef;
}

sub remove_follower_id {
    my ( $self, $id ) = @_;

    delete $self->state->followers->{$id};
}

sub is_follower_id {
    my ( $self, $id ) = @_;

    return exists $self->state->followers->{$id};
}

sub twitter_screen_name { shift->authenticated_user->{screen_name} }
sub twitter_id          { shift->authenticated_user->{id} }

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

sub connect_twitter_stream {
    my $self = shift;

    $self->log->trace('connect_twitter_stream');

    my $w; $w = AnyEvent::Twitter::Stream->new(
        $self->_twitter_auth,
        token        => $self->state->access_token,
        token_secret => $self->state->access_token_secret,
        method       => 'userstream',
        timeout      => $self->twitter_stream_timeout,
        on_connect   => sub {
            $self->twitter_stream_watcher($w);
            $self->log->info('Connected to Twitter');
            $self->reconnect_delay(0);
        },
        on_eof       => sub {
            $self->log->trace("on_eof");
            $self->bot_notice($self->irc_channel, "Twitter stream disconnected");
            $self->connect_twitter_stream if $self->has_twitter_stream_watcher;
        },
        on_error   => sub {
            undef $w;
            my $e = shift;
            $self->log->error("on_error: $e");
            $self->bot_notice($self->irc_channel, "Twitter stream error: $e");
            if ( $e =~ /^420:/ ) {
                $self->log->fatal("excessive login rate; shutting down");
                $self->call('poco_shutdown');
            }

            # progressively backoff on reconnection attepts to max_reconnect_delay
            if ( my $delay = $self->reconnect_delay ) {
                $self->log->debug("delaying $delay seconds before reconnecting");
            }
            my $t; $t = AE::timer $self->reconnect_delay, 0, sub {
                undef $t;
                my $next_delay = $self->reconnect_delay * 2 || 1;
                $next_delay = $self->max_reconnect_delay if $next_delay > $self->max_reconnect_delay;
                $self->reconnect_delay($next_delay);
                $self->connect_twitter_stream;
            };
        },
        on_keepalive   => sub {
            $self->log->trace("on_keepalive");
        },
        on_friends   => sub {
            $self->log->trace("on_friends: ", JSON->new->encode(@_));
            $self->yield(friends_ids => shift);
        },
        on_event     => sub {
            my $msg = shift;

            $self->log->trace("on_event: $$msg{event}");
            $self->yield(on_event => $msg);
        },
        on_tweet     => sub {
            my $msg = shift;

            $self->log->trace("on_tweet");

            if ( exists $$msg{sender} ) {
                $self->log->debug('received old style direct_message');
                $self->yield(on_direct_message => $msg);
            }
            elsif ( exists $$msg{text} ) {
                $self->yield(on_tweet => $msg);
            }
            elsif ( exists $$msg{direct_message} ) {
                $self->yield(on_direct_message => $$msg{direct_message});
            }
            elsif ( exists $$msg{limit} ) {
                $self->log->warn("track limit: $$msg{limit}{track}");
                $self->bot_notice($self->irc_channel,
                    "Track limit received - $$msg{limit}{track} statuses missed.");
            }
            elsif ( exists $$msg{scrub_geo} ) {
                # $$msg{scrub_geo} = {"user_id":14090452,"user_id_str":"14090452","up_to_status_id":23260136625,"up_to_status_id_str":"23260136625"}
                my $e = $$msg{scrub_geo};
                $self->log->info("scrub_geo: user_id=$$e{user_id}, up_to_status_id=$$e{up_to_status_id}");
            }
            else {
                $self->log->error("unexpected message: ", JSON->new->pretty($msg));
                $self->bot_notice($self->irc_channel, "Unexpected twitter packet, see the log for details");
            }
        },
        on_delete    => sub {
            $self->log->trace("on_delete");
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
                _stop  => sub { $self->log->trace('[ircd:stop]') },
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

    $self->get_authenticated_user;
    $self->connect_twitter_stream;

    return $self;
}

# Without detaching the ircd child session, the application will not
# shut down.  Bug in PoCo::Server::IRC?
event _child => sub {
    my ($self, $kernel, $event, $child) = @_[OBJECT, KERNEL, ARG0, ARG1];

    $self->log->trace("[_child] $event $child");
    $kernel->detach_child($child) if $event eq 'create';
};

event poco_shutdown => sub {
    my ($self) = @_;

    $self->log->trace("[poco_shutdown]");
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

    $self->log->trace("[ircd_daemon_nick] $nick");

    # if it's a nick change, we only get ARG0 and ARG1
    return unless defined $_[ARG2];
    return if $self->ircd->_state_user_route($nick) eq 'spoofed';

    $self->irc_nickname($nick);

    # Abuse!  Calling the private implementation of ircd to force-join the connecting
    # user to the twitter channel. ircd set's it's heap to $self: see ircd's perldoc.
    $sender->get_heap->_daemon_cmd_join($nick, $self->irc_channel);

    # Give the user half ops (just a visual cue)
    $self->post_ircd(daemon_cmd_mode => $self->irc_botname, $self->irc_channel, '+h', $nick);
};

event ircd_daemon_join => sub {
    my($self, $sender, $user, $ch) = @_[OBJECT, SENDER, ARG0, ARG1];

    $self->log->trace("[ircd_daemon_join] $user, $ch");
    return unless my($nick) = $user =~ /^([^!]+)!/;
    return if $self->ircd->_state_user_route($nick) eq 'spoofed';

    if ( $ch eq $self->irc_channel ) {
        $self->joined(1);
        $self->log->trace("    joined!");
        return;
    }
    elsif ( $self->log_channel && $ch eq $self->log_channel ) {
        my $appender = Log::Log4perl->appender_by_name('twirc-logger');
        $appender->dump_history;
    }
    else {
        $self->log->trace("    ** part **");
        # only one channel allowed
        $sender->get_heap()->_daemon_cmd_part($nick, $ch);
    }
};

event ircd_daemon_part => sub {
    my($self, $user_name, $ch) = @_[OBJECT, ARG0, ARG1];

    return unless my($nick) = $user_name =~ /^([^!]+)!/;
    return if $nick eq $self->irc_botname;

    if ( my $user = $self->get_user_by_nick(lc $nick) ) {
        $self->delete_user($user);
    }

    $self->joined(0) if $ch eq $self->irc_channel && $nick eq $self->irc_nickname;
};

event ircd_daemon_quit => sub {
    my($self, $user) = @_[OBJECT, ARG0];

    $self->log->trace("[ircd_daemon_quit]");
    return unless my($nick) = $user =~ /^([^!]+)!/;
    return if $self->get_user_by_nick(lc $nick);
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

    $self->log->trace("[ircd_daemon_public] $nick: $text");
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

    unless ( $self->get_user_by_nick(lc $target_nick) ) {
        # TODO: handle the error the way IRC would?? (What channel?)
        $self->bot_says($self->irc_channel, qq/You don't appear to be following $target_nick; message not sent./);
        return;
    }

    $self->twitter(new_direct_message => { user => $target_nick, text => $text });
};

event friend_join => sub {
    my ( $self, $friend ) = @_[OBJECT, ARG0];

    my $nick = $$friend{screen_name};
    $self->log->trace("friend_join: $nick");

    $self->post_ircd(add_spoofed_nick => { nick => $nick, ircname => $$friend{name} })
        unless $self->ircd->state_nick_exists($nick);

    $self->post_ircd(daemon_cmd_join => $nick, $self->irc_channel);
    if ( $self->is_follower_id($$friend{id}) ) {
        $self->post_ircd(daemon_cmd_mode => $self->irc_botname, $self->irc_channel, '+v', $nick);
    }
};

event lookup_friends => sub {
    my ( $self, $ids ) = @_[OBJECT, ARG0];

    return unless @$ids;

    my $fresh = time;
    my $r = $self->twitter(lookup_users => { user_id => $ids });
    for my $friend ( @{$r || []} ) {
        delete $friend->{status};
        $self->add_user($friend);
        $self->yield(friend_join => $friend);
    }

    $self->state->store($self->state_file) if $self->state_file;
};

event get_followers_ids => sub {
    my ( $self ) = $_[OBJECT];

    my %followers;
    for ( my $cursor = -1; $cursor; ) {
        if ( my $r = $self->twitter(followers_ids => { cursor => $cursor }) ) {
            for my $id ( @{$$r{ids}} ) {
                $followers{$id} = undef;
            }
            $cursor = $$r{next_cursor};
        }
        else {
            $cursor = 0;
        }
    }

    $self->state->followers(\%followers);
    $self->state->followers_updated_at(time);

    $self->yield('set_voice');
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
        my $friend = $self->state->twitter_users->{$id};
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

    unless ( $self->ircd->state_is_chan_member($nick, $self->irc_channel) ) {
        $self->post_ircd(daemon_cmd_join => $nick, $self->irc_channel);
    }

    $self->log->trace("on_tweet: <$nick> $text");
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
    $self->log->debug("unhandled event", JSON->new->pretty->encode($msg));
};

sub on_event_follow {
    my ( $self, $event ) = @_;

    if ( my $source = $$event{source} ) {
        my $target = $$event{target} || return;

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
        $self->log->info('direct message sent to @', $$msg{recipient_screen_name});
        return;
    }

    my $nick = $$msg{sender_screen_name};
    my $sender = $$msg{sender};

    unless ( $self->ircd->state_nick_exists($nick) ) {
        # This shouldn't happen - twitter only allows direct messages to followers, so
        # we *should* already have $nick on board.
        $self->post_ircd(add_spoofed_nick => { nick => $nick, ircname => $$sender{name} });
        $self->add_user($sender);
    }

    my $text = $self->formatted_status_text($msg);
    $self->post_ircd(daemon_cmd_privmsg => $nick, $self->irc_nickname, $_)
            for split /\r?\n/, $text;
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

    $self->log->trace("[cmd_post_status]");

    return if $self->status_text_too_long($channel, $text);

    my $status = $self->twitter(update => $text) || return;

    $self->log->trace("    update returned $status");
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

    $self->twitter(create_friend => $id);
};

=item unfollow I<id>

Stop following Twitter user I<id>.  In Twitter, parlance, this destroys a
friendship.

=cut

event cmd_unfollow => sub {
    my ($self, $channel, $id) = @_[OBJECT, ARG0, ARG1];

    my $user = $self->get_user_by_nick(lc $id);
    unless ( $user ) {
        $self->bot_says($channel, qq/You don't appear to be following $id./);
        return;
    }

    $self->twitter(destroy_friend => $id) || return;

    $self->post_ircd(daemon_cmd_part => $id, $self->irc_channel);
    $self->post_ircd(del_spooked_nick => $id);
    $self->bot_notice($channel, qq/No longer following $id./);
    $self->delete_user($user);
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

    $self->log->trace("[cmd_whois] $nick");

    my $user = $self->get_user_by_nick(lc $nick);
    unless ( $user ) {
        $self->log->trace("     $nick not in users; fetching");
        $user = $self->twitter(show_user => { screen_name => $nick });
    }

    if ( $user ) {
        $self->bot_says(
            $channel,
            sprintf('%s [%s]: %s, %s', @{$user}{qw/screen_name id name location description url/})
        );
    }
    else {
        $self->bot_says($channel, "I don't know $nick.");
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
        $self->twitter($method => { id => $nick });
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
    $count ||= $self->selection_count;

    $self->log->trace("[cmd_favorite] $nick");

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

    $self->log->trace("[handle_favorite] $index");

    my @candidates = @{$self->stash->{candidates} || []};
    if ( $index =~ /^\d+$/ && 0 < $index && $index <= @candidates ) {
        $self->twitter(create_favorite => { id => $candidates[$index - 1] });
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

    $count ||= $self->selection_count;

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

    $message = "\@$nick $message";
    return if $self->status_text_too_long($channel, $message);

    $count ||= $self->selection_count;

    my $recent = $self->twitter(user_timeline => { screen_name => $nick, count => $count }) || return;
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
        $self->bot_says($channel, "[$_] " . elide($recent->[$_ - 1]{text}, $self->truncate_to));
    }
};

sub _handle_reply {
    my ($self, $channel, $index) = @_;

    my @candidates = @{$self->stash->{candidates} || []};
    if ( $index =~ /^\d+$/ && 0 < $index && $index <= @candidates ) {
        $self->twitter(update => {
            status                => $self->stash->{message},
            in_reply_to_status_id => $candidates[$index - 1],
        });
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

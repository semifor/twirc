package POE::Component::Server::Twirc;
use MooseX::POE;

use LWP::UserAgent::POE;
use POE qw(Component::Server::IRC);
use Net::Twitter;
use Email::Valid;
use Text::Truncate;

with 'MooseX::Log::Log4perl';

# Net::Twitter returns text with encoded HTML entities.  I *think* decoding
# properly belongs in Net::Twitter.  So, if it gets added, there:
# TODO: remove HTML::Entities and decode_entities calls.
use HTML::Entities;

our $VERSION = '0.03';

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


=item irc_mask

The IRC user/host mask used to restrict connecting users.  Defaults to C<*@127.0.0.1>.

=cut

has irc_mask            => ( isa => 'Str', is => 'ro', default => '*@127.0.0.1' );


=item irc_password

Password used to authenticate to the IRC server.

=cut

has irc_password        => ( isa => 'Str', is => 'ro' );


=item irc_botname

The name of the channel operator bot.  Defaults to C<tweeter>.  Select a name
that does not conflict with friends, followers, or your own IRC nick.

=cut

has irc_botname         => ( isa => 'Str', is => 'ro', default => 'tweeter' );


=item irc_botircname

Text to be used as the channel operator bot's IRC full name.

=cut

has irc_botircname      => ( isa => 'Str', is => 'ro', default => 'Your friendly Twitter Agent' );


=item irc_channel

The name of the channel to use.  Defaults to C<&twitter>.

=cut

has irc_channel         => ( isa => 'Str', is => 'ro', default => '&twitter' );


=item twitter_retry

The number of seconds between polls for new status updates.  Defaults to 300
(5 minutes).

=cut

has twitter_retry       => ( isa => 'Int', is => 'ro', default => 300 );


=item twitter_retry_on_error

The number of seconds to wait before retrying a failed poll for friends,
followers, or status updates.  Defaults to 60 (1 minute).

=cut

has twitter_retry_on_error => ( isa => 'Int', is => 'ro', default => 60 );


=item twitter_alias

An alias to use for displaying incoming status updates from the owning user.
This is necessary if the user's IRC nickname and Twitter screen name are the
same.  Defaults to C<me>.

=cut

has twitter_alias       => ( isa => 'Str', is => 'ro', default => 'me' );

=item echo_posts

If false, posts sent by L<POE::Component::Server::Twirc> will not be redisplayed when received
is the friends_timeline.  Defaults to false.

Set C<echo_posts(1)> to see your own tweets in chronological order with the others.

=cut

has echo_posts => ( isa => 'Bool', is => 'rw', default => 0 );

=item favorites_count

How many favorites candidates to display for selection. Defaults to 3.

=cut

has favorites_count => ( isa => 'Int', is => 'ro', default => 3 );

=item truncate_to

When displaying tweets for selection, they will be truncated to this length.
Defaults to 60.

=cut

has truncate_to         => ( isa => 'Int', is => 'ro', default => 60 );

=item check_replies

Experimental!
If true, checks for @replies when polling for friends' timeline updates
and merges them with normal status updates.  Normally, only replies from
friends are displayed.  This provides the display of @replies from
users not followed.  It comes at the expense of an additional API call
on each timeline poll, so keep that in mind when setting L<twitter_retry>.
Twitter imposes an API call limit of 100 calls per hour.

This also has the effect of adding senders of @replies to the channel,
even though they are not followed.

=cut

has check_replies => ( isa => 'Bool', is => 'rw', default => 0 );

=back

=cut

has _ircd => (
       accessor => 'ircd', isa => 'POE::Component::Server::IRC', is => 'rw', weak_ref => 1 );
has _twitter => (
       accessor => 'twitter',  isa => 'Net::Twitter', is => 'rw' );
has _users => (
       accessor => 'users', isa => 'HashRef[Str]', is => 'rw', lazy => 1, default => sub { {} } );
has _joined => (
       accessor => 'joined', isa => 'Bool', is => 'rw', default => 0 );
has _stack => (
       accessor => 'stack', isa => 'ArrayRef[HashRef]', is => 'rw', default => sub { [] } );
has _friends_timeline_since_id => (
       accessor => 'friends_timeline_since_id', isa => 'Int', is => 'rw' );
has _last_user_timeline_id => (
       accessor => 'last_user_timeline_id', isa => 'Int', is => 'rw', default => 0 );
has _replies_since_id => (
       accessor => 'replies_since_id', isa => 'Int', is => 'rw' );
has _stash => (
       accessor => 'stash', isa => 'Maybe[HashRef]', is => 'rw' );

sub post_ircd {
    my $self = shift;
    $self->ircd->yield(@_);
}

sub bot_says  {
    my ($self, $text) = @_;

    $self->post_ircd('daemon_cmd_privmsg', $self->irc_botname, $self->irc_channel, $text);
};

sub twitter_error {
    my ($self, $text) = @_;

    $self->post_ircd(daemon_cmd_notice =>
        $self->irc_botname, $self->irc_channel, "Twitter error: $text");
};

# set topic from status, iff newest status
sub set_topic {
    my ($self, $status) = @_;

    return unless $status->{id} > $self->last_user_timeline_id;

    $self->post_ircd(daemon_cmd_topic => $self->irc_botname, $self->irc_channel,
           decode_entities($status->{text}));
    $self->last_user_timeline_id($status->{id});
};

# match any nick
sub nicks_alternation {
    my $self = shift;

    return join '|', map quotemeta, keys %{$self->users};
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
    $self->post_ircd('add_listener', port => $self->irc_server_port);

    # add super user
    $self->post_ircd(
        add_spoofed_nick =>
        { nick => $self->irc_botname, ircname => $self->irc_botircname }
    );
    $self->post_ircd(daemon_cmd_join => $self->irc_botname, $self->irc_channel);
    $self->yield('friends');
    $self->yield('delay_friends_timeline');

    $self->twitter(Net::Twitter->new(
        useragent_class => 'LWP::UserAgent::POE',
        username => $self->twitter_username,
        password => $self->twitter_password,
        useragent => 'TwitIrc (alpha)',
    ));

    return $self;
}

sub DEFAULT {
    my ($self, $event) = @_[KERNEL, ARG0];

    $self->bot_says(qq/I don't understand "$1". Try "help"./)
        if $event =~ /^cmd_(\S+)/;
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

    $self->log->debug("[poco_shutdown]\n");
    $_[KERNEL]->alarm_remove_all();
    $self->post_ircd('unregister');
    $self->post_ircd('shutdown');
};

########################################################################
# IRC events
########################################################################

event ircd_daemon_nick => sub {
    my ($self, $sender, $nick, $new_nick, $host) = @_[OBJECT, SENDER, ARG0, ARG1, ARG5];

    $self->log->debug("[ircd_daemon_nick] $nick, $new_nick, $host\n");

    return if $nick eq $self->irc_botname;

    $self->log->debug("\tnick = $nick\n");

    # Abuse!  Calling the private implementation of ircd to force-join the connecting
    # user to the twitter channel. ircd set's it's heap to $self: see ircd's perldoc.
    $sender->get_heap()->_daemon_cmd_join($nick, $self->irc_channel);
};

event ircd_daemon_join => sub {
    my($self, $sender, $user, $ch) = @_[OBJECT, SENDER, ARG0, ARG1];

    $self->log->debug("[ircd_daemon_join] $user, $ch\n");
    return unless my($nick) = $user =~ /^([^!]+)!/;
    return if $self->users->{$nick};
    return if $nick eq $self->irc_botname;

    if ( $ch eq $self->irc_channel ) {
        $self->joined(1);
        $self->log->debug("\tjoined!\n");
        $self->yield('throttle_messages');
        return;
    }
    $self->log->debug("\t** part **\n");
    # only one channel allowed
    $sender->get_heap()->_daemon_cmd_part($nick, $ch);
};

event ircd_daemon_part => sub {
    my($self, $user, $ch) = @_[OBJECT, ARG0, ARG1];

    return unless my($nick) = $user =~ /^([^!]+)!/;
    return if $self->users->{$nick};
    return if $nick eq $self->irc_botname;

    $self->joined(0) if $ch eq $self->irc_channel;
};

event ircd_daemon_quit => sub {
    my($self, $user) = @_[OBJECT, ARG0];

    $self->log->debug("[ircd_daemon_quit]\n");
    return unless my($nick) = $user =~ /^([^!]+)!/;
    return if $self->users->{$nick};
    return if $nick eq $self->irc_botname;

    $self->joined(0);
    $self->yield('poco_shutdown');
};

event ircd_daemon_public => sub {
    my ($self, $user, $channel, $text) = @_[OBJECT, ARG0, ARG1, ARG2];

    my $nick = ( $user =~ m/^(.*)!/)[0];
    $self->log->debug("[ircd_daemon_public] $nick: $text\n");
    return unless $nick eq $self->irc_nickname;

    # give any command handler a shot
    if ( $self->stash ) {
        $self->log->debug("stash exists...");
        my $handler = delete $self->stash->{handler};
        if ( $handler ) {
            return if $self->$handler($text); # handled
        }
        else {
            $self->log->error("stash exsits with no handler");
        }
        # the user ignored a command completion request, kill it
        $self->stash(undef);
    }

    # treat "nick: ..." as "post @nick ..."
    my $nick_alternation = $self->nicks_alternation;
    if ( $text =~ s/^($nick_alternation):\s+/\@$1 /i ) {
        $self->yield(cmd_post => $text);
        return;
    }

    my ($command, $arg) = split /\s/, $text, 2;
    if ( $command =~ /^\w+$/ ) {
        $arg =~ s/\s+$// if $arg;
        $self->yield("cmd_$command", $arg);
    }
    else {
        $self->bot_says(qq/That doesn't look like a command. Try "help"./);
    }
};

event ircd_daemon_privmsg => sub {
    my ($self, $user, $target_nick, $text) = @_[OBJECT, ARG0..ARG2];

    # owning user is the only one allowed to send direct messages
    my $me = $self->irc_nickname;
    return unless $user =~ /^\Q$me\E!/;

    unless ( $self->users->{$target_nick} ) {
        $self->bot_says(qq/You don't appear to be following $target_nick; message not sent./);
        return;
    }

    unless ( eval { $self->twitter->new_direct_message({ user => $target_nick, text => $text }) } ) {
        $self->twitter_error("new_direct_message failed.");
    }
};

########################################################################
# Twitter events
########################################################################

# This is the main loop; check for updates every twitter_retry seconds.
event delay_friends_timeline => sub {
    my ($self) = @_;

    $self->yield('friends_timeline');
    $_[KERNEL]->delay(delay_friends_timeline => $self->twitter_retry);
};

event throttle_messages => sub {
    my ($self) = @_;

    $self->log->debug("[throttle_messages] ", scalar @{$self->stack}, " messages\n");

    for my $entry ( @{$self->stack} ) {
        my @lines = split /\r?\n/, $entry->{text};
        $self->post_ircd(daemon_cmd_privmsg => $entry->{name}, $self->irc_channel, $_)
            for @lines;
    }

    $self->stack([]);
};

# Add friends to the channel
event friends => sub {
    my ($self, $page ) = @_[OBJECT, ARG0];

    my $retry = $self->twitter_retry_on_error;

    $self->log->debug("[twitter:friends] calling...\n");
    $page ||= 1;
    while ( my $friends = eval { $self->twitter->friends({page => $page}) } ) {
        unless ( $friends ) {
            $self->twitter_error("request for friends failed; retrying in $retry seconds");
            $_[KERNEL]->delay(friends => $retry);
            return;
        }
        ++$page;

        $self->log->debug("\tfriends returned ", scalar @$friends, " friends\n");

        # Current API gets 100 friends per page.  If we have exactly 100 friends
        # we have to try again with page=2 and we should get (I'm assuming, here)
        # an empty arrayref.  What if the API changes to 200, etc.?  Might as well
        # just loop until we get an empty arrayref.  That will handle either case.
        last unless @$friends;

        for my $friend ( @$friends ) {
            my ($nick, $name) = @{$friend}{qw/screen_name name/};

            next if $self->users->{$nick};
            $self->post_ircd(add_spoofed_nick => { nick => $nick, ircname => $name });
            $self->post_ircd(daemon_cmd_join => $nick, $self->irc_channel);
            $self->users->{$nick} = $friend;
        }
        last;
    }
    $self->yield('followers');
};

# Give friends who are also followers voice; it's just a visual hint to the user.
event followers => sub {
    my ($self, $page ) = @_[OBJECT, ARG0];

    my $retry = $self->twitter_retry_on_error;

    $self->log->debug("[twitter:followers] calling...\n");
    $page ||= 1;
    while ( my $followers = eval { $self->twitter->followers({page => $page}) } ) {
        $self->log->debug("\tpage: $page\n");
        unless ( $followers ) {
            $self->twitter_error("request for followers failed; retrying in $retry seconds");
            $_[KERNEL]->delay(followers => $retry, $page);
            return;
        }
        ++$page;

        $self->log->debug("\tfollowers returned ", scalar @$followers, " followers\n");

        # see comments for event friends
        last unless @$followers;

        for my $follower ( @$followers ) {
            my $nick = $follower->{screen_name};
            if ( $self->users->{$nick} ) {
                $self->post_ircd(daemon_cmd_mode =>
                    $self->irc_botname, $self->irc_channel, '+v', $nick);
            }
        }
    }
};

event friends_timeline => sub {
    my ($self) = @_;

    $self->log->debug("[friends_timeline] \n");

    my $statuses = eval {
        $self->twitter->friends_timeline({
            since_id => $self->friends_timeline_since_id
        });
    };

    unless ( $statuses ) {
        $self->twitter_error('friends_timeline request failed');
        return;
    }

    $self->log->debug("\tfriends_timeline returned ", scalar @$statuses, " statuses\n");
    $self->friends_timeline_since_id($statuses->[0]{id}) if @$statuses;

    $statuses = $self->merge_replies($statuses);

    my $channel = $self->irc_channel;
    my $new_topic;
    for my $status (reverse @{ $statuses }) {
        my ($name, $ircname) = @{$status->{user}}{qw/screen_name name/};
        my $text = decode_entities($status->{text});

        # alias our twitter_name if configured
        # (to avoid a collision in case our twitter screen name and irc nick are the same)
        $self->log->debug("\t\$name = $name, \$twitter_name = "), $self->twitter_screen_name;

        # TODO: is this even necessary? Can we just send a privmsg from a real user?
        if ( $name eq $self->twitter_screen_name ) {
            $new_topic = $status;
            $name = $self->twitter_alias if $self->twitter_alias;
            next if !$self->echo_posts && $status->{id} <= $self->last_user_timeline_id;
        }

        unless ( $self->users->{$name} ) {
            $self->post_ircd(add_spoofed_nick => { nick => $name, ircname => $ircname });
            $self->post_ircd(daemon_cmd_join => $name, $channel);
        }
        $self->users->{$name} = $status->{user};

        $self->log->debug("\t{ $name, $text }\n");
        push @{ $self->stack }, { name => $name, text => $text }
    }
    $self->set_topic($new_topic) if $new_topic;
    $self->yield('user_timeline') unless $self->last_user_timeline_id;
    $self->yield('throttle_messages') if $self->joined;
};

sub merge_replies {
    my ($self, $statuses) = @_;
    return $statuses unless $self->check_replies;

    # TODO: find a better way to initialize this??
    unless ( $self->replies_since_id ) {
        $self->replies_since_id(
            @$statuses ? $statuses->[-1]{id} : $self->last_user_timeline_id
         );
    }

    my $replies = eval {$self->twitter->replies({ since_id => $self->replies_since_id }) };
    if ( $replies && @$replies ) {
        $self->log->debug("[merge_replies] ", scalar @$replies, " replies");

        $self->replies_since_id($replies->[0]{id});

        # TODO: clarification needed: I'm assuming we get replies
        # from friends in *both* friends_timeline and replies,
        # so, we need to weed them.
        my %seen = map { ($_->{id}, $_) } @{$statuses}, @{$replies};

        $statuses = [ sort { $b->{id} <=> $a->{id} } values %seen ];
    }
    return $statuses;
}

event user_timeline => sub {
    my ($self) = @_;

    $self->log->debug("[user_timetline] calling...\n");
    my $statuses = eval { $self->twitter->user_timeline({ count => 1}) } || return;
    unless ( $statuses ) {
        $self->twitter_error('user_timeline request failed; retrying in 60 seconds');
        $_[KERNEL]->delay(user_timeline => 60);
    }

    $self->log->debug("\turser_timeline returned\n");
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
    my ($self, $text) = @_[OBJECT, ARG0];

    $self->log->debug("[cmd_post_status]");

    if ( (my $n = length($text) - 140) > 0 ) {
        $self->bot_says("Message not sent; $n characters too long. Limit is 140 characters.");
        return;
    }

    my $status = eval { $self->twitter->update($text) };
    unless ( $status ) {
        $self->twitter_error('status update failed; try again later');
        return;
    }

    $self->log->debug("\tupdate returned $status\n");

    $self->set_topic($status);
};

=item follow I<id>

Follow a new Twitter user, I<id>.  In Twitter parlance, this creates a friendship.

=cut

event cmd_follow => sub {
    my ($self, $id) = @_[OBJECT, ARG0];

    if ( $self->users->{$id} ) {
        $self->bot_says(qq/You're already following $id./);
        return;
    }
    elsif ( $id !~ /^\w+$/ ) {
        $self->bot_says(qq/"$id" doesn't look like a user ID to me./);
        return;
    }

    my $friend = eval { $self->twitter->create_friend($id) };
    unless ( $friend ) {
        $self->twitter_error('create_friend failed');
        return;
    }

    my ($nick, $name) = @{$friend}{qw/screen_name name/};
    $self->post_ircd('add_spoofed_nick', { nick => $nick, ircname => $name });
    $self->post_ircd(daemon_cmd_join => $name, $self->irc_channel);
    $self->users->{$nick} = $friend;

    if ( eval { $self->twitter->relationship_exists($nick, $self->twitter_screen_name) } ) {
        $self->post_ircd(daemon_cmd_mode =>
            $self->irc_botname, $self->irc_channel, '+v', $nick);
    }
};

=item unfollow I<id>

Stop following Twitter user I<id>.  In Twitter, parlance, this destroys a
friendship.

=cut

event cmd_unfollow => sub {
    my ($self, $id) = @_[OBJECT, ARG0];

    if ( !$self->users->{$id} ) {
        $self->bot_says(qq/You don't appear to be following $id./);
        return;
    }

    my $friend = eval { $self->twitter->destroy_friend($id) };
    unless ( $friend ) {
        $self->twitter_error('destroy_friend failed');
        return;
    }

    $self->post_ircd(daemon_cmd_part => $id, $self->irc_channel);
    $self->post_ircd(del_spooked_nick => $id);
    delete $self->users->{$id};
};

=item block I<id>

Block Twitter user I<id>.

=cut

event cmd_block => sub {
    my ($self, $id) = @_[OBJECT, ARG0];

    if ( $id !~ /^\w+$/ ) {
        $self->bot_says(qq/"$id" doesn't look like a user ID to me./);
        return;
    }

    unless ( eval { $self->twitter->create_block($id) } ) {
        $self->twitter_error('create_block failed');
        return;
    }

    if ( $self->users->{$id} ) {
        $self->post_ircd(daemon_cmd_mode =>
            $self->irc_botname, $self->irc_channel, '-v', $id);
    }
};

=item unblock I<id>

Stop blocking Twitter user I<id>.

=cut

event cmd_unblock => sub {
    my ($self, $id) = @_[OBJECT, ARG0];

    if ( $id !~ /^\w+$/ ) {
        $self->bot_says(qq/"$id" doesn't look like a user ID to me./);
        return;
    }

    unless ( eval { $self->twitter->destroy_block($id) } ) {
        $self->twitter_error('destroy_block failed');
        return;
    }

    if ( $self->users->{id} ) {
        $self->post_ircd(daemon_cmd_mode =>
            $self->irc_botname, $self->irc_channel, '+v', $id);
    }
};

=item whois I<id>

Displays information about Twitter user I<id>, including name, location, and
description.

=cut

event cmd_whois => sub {
    my ($self, $id) = @_[OBJECT, ARG0];

    $self->log->debug("[cmd_whois] $id");

    my $user = $self->users->{$id};
    unless ( $user ) {
        $self->log->debug("\t $id not in users; fetching");
        my $arg = Email::Valid->address($id) ? { email => $id } : { id => $id };
        $user = eval { $self->twitter->show_user($arg) };
    }
    if ( $user ) {
        $self->bot_says("$user->{screen_name} [$user->{id}]: $user->{name}, $user->{location}");
        for ( @{$user}{qw/description url/} ) {
            $self->bot_says($_) if $_;
        }
    }
    else {
        $self->bot_says("I don't know $id.");
    }
};

=item notify I<on|off> I<id ...>

Turns device notifications on or off for the list of Twitter IDs.

=cut

event cmd_notify => sub {
    my ($self, $argstr) = @_[OBJECT, ARG0];

    my @nicks = split /\s+/, $argstr;
    my $onoff = shift @nicks;

    unless ( $onoff && $onoff =~ /^on|off$/ ) {
        $self->bot_says("Usage: notify [on|off] nick[ nick [...]]");
        return;
    }

    my $method = $onoff eq 'on' ? 'enable_notifications' : 'disable_notifications';
    for my $nick ( @nicks ) {
        unless ( eval { $self->twitter->$method({ id => $nick }) } ) {
            $self->twitter_error("notify $onoff failed for $nick");
        }
    }
};

=item favorite I<friend> [I<count>]

Mark I<friend>'s tweet as a favorite.  Optionally, specify the number of tweets
to display for selection with I<count> (Defaults to 3.)

=cut

event cmd_favorite => sub {
    my ($self, $args) = @_[OBJECT, ARG0];

    my ($nick, $count) = split /\s+/, $args;
    $count ||= $self->favorites_count;

    $self->log->debug("[cmd_favorite] $nick");

    unless ( $self->users->{$nick} ) {
        $self->bot_says("You're not following $nick.");
        return;
    }

    my $recent = eval { $self->twitter->user_timeline({ id => $nick, count => $count }) };
    unless ( $recent ) {
        $self->twitter_error('user_timeline failed');
        return;
    }
    if ( @$recent == 0 ) {
        $self->bot_says("$nick has no recent tweets");
        return;
    }

    $self->stash({
        favorite_candidates => [ map $_->{id}, @$recent ],
        handler => 'handle_favorite',
    });

    $self->bot_says('Which tweet?');
    for ( 1..@$recent ) {
        $self->bot_says("[$_] " . truncstr($recent->[$_ - 1]{text}, $self->truncate_to));
    }
};

sub handle_favorite {
    my ($self, $index) = @_;

    $self->log->debug("[handle_favorite] $index");

    my @favorite_candidates = @{$self->stash->{favorite_candidates} || []};
    if ( $index =~ /^\d+$/ && 0 < $index && $index <= @favorite_candidates ) {
        if ( eval { $self->twitter->create_favorite({
                    id => $favorite_candidates[$index - 1]
                }) } ) {
            $self->post_ircd(daemon_cmd_notice =>
                $self->irc_botname, $self->irc_channel, 'favorite added');
        }
        else {
            $self->bot_says('create_favorite failed');
        }
        $self->stash(undef);
        return 1; # handled
    }
    return 0; # unhandled
};

=item check_replies I<on|off>

Turns reply checking on or off.  See L<checke_replies> in configuration.

=cut

event cmd_check_replies => sub {
    my ($self, $onoff) = @_[OBJECT, ARG0];

    unless ( $onoff && $onoff =~ /^on|off$/ ) {
        $self->bot_says("Usage: check_replies [on|off]");
        return;
    }
    $self->check_replies($onoff eq 'on' ? 1 : 0);
};

=item help

Display a simple help message

=cut

event cmd_help => sub {
    my ($self, $argstr)=@_[OBJECT, ARG0];
    $self->bot_says("Available commands:");
    $self->bot_says(join ' ' => sort qw/
        post follow unfollow block unblock whois notify refresh favorite
        check_replies
    /);
    $self->bot_says('/msg nick for a direct message.')
};

event cmd_refresh => sub {
    my ($self) = @_;

    $self->yield('delay_friends_timeline');
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

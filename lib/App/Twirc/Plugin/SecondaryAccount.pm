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

__END__

=head1 NAME

App::Twirc::Plugin::SecondaryAccount - Cross post updates to another account

=head1 SYNOPSIS

  # in config (.yml in this example)
  plugins:
      - SecondaryAccount
          username: my_other_screen_name
          password: my_other_twitter_password
          option: fb
      - SecondaryAccount
          username: yet_another_screen_name
          password: yet_another_password
          net_twitter_options:
              apiurl: http://identi.ca/api

  # In your IRC client...
  # ...post to your primary account *and* yet_another_screen_name
  post Hello, world!

  # ...post to your primary account and both secondary accounts
  post -fb Hello, universe!

  # ... post to my_other_screen name, only
  post -fbonly Hello, alternate reality.

=head1 DESCRIPTION

This plugin allows cross-posting messages to multiple accounts.  In
configuration, you can provide an C<option> value.  When used as an option to
C<post>, your message will be cross-posted to your primary account and the
secondary account with that C<option> value.  If you do not provide an
C<option> value, all messages are cross-posted to the secondary account.

By appending C<only> to the C<option> value, your status will only be posted to
the the account with that C<option> value.

I use a configuration similar to the one in the synopsis to cross-post my
Twitter status updates to Identi.ca, and optionally to Facebook.  My Twitter
screen name is C<semifor>.  I created an account with screen name C<semifor_fb>
and registered it with Twitter's Facebook application.  In the C<twirc>
configuration file, I assigned C<option> value C<fb> to the account.

I created another secondary account with my Identi.ca screen name.  In C<twirc>
configuration, I used the C<net_twitter_options> to specify Identi.ca's
C<apiurl>.

Now, when I post a normal status update, it is posted to C<semifor> on both
Twitter and Identi.ca.  If I include a C<-fb> option to post, my status update
is posted to Twitter, Identi.ca, and Facebook.  If I add a C<-fbonly> option to
C<post>, my status update is only posted to the Facebook account.

=head1 AUTHOR

Marc Mims <marc@questright.com>

=head1 LICENSE

Copyright (c) 2009 Marc Mims

You may distribute this code and/or modify it under the same terms as Perl itself.

=cut

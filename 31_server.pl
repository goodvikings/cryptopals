#!/usr/bin/perl

use strict;
use warnings;

use Digest::HMAC_SHA1;
use HTTP::Daemon;
use HTTP::Response;
use Time::HiRes qw(usleep);

use Data::Dumper;

my $key = genRandomKey();

print getHmac({file => "passwd"}) . "\n";

my $d = HTTP::Daemon->new(LocalPort => shift) || die;
my $sleep = shift || 50;

print "Please contact me at: <URL:", $d->url, ">\n";
while (my $c = $d->accept) {
	while (my $r = $c->get_request) {
		if ($r->method eq 'GET') {
			my %form = $r->uri->query_form();
			unless (defined $form{file} && defined $form{signature}) {
				$c->send_response(HTTP::Response->new(500));
				$c->close();
				next;
			}

			my $hmac = getHmac({file => $form{file}});

			unless (insecureCompare({signature => $form{signature}, hmac => $hmac, sleepTime => $sleep})) {
				$c->send_response(HTTP::Response->new(500));
				$c->close();
				next;
			}

			my $resp = HTTP::Response->new(200);
			$c->send_response($resp);
			$c->close();
		}
	}
	undef $c;
}

sub genRandomKey {
	my $key;

	$key .= chr(int(rand(256))) for (0 .. int(rand(30) + 10));

	return $key;
}

sub getHmac {
	(my $args) = @_;

	my $hmac = Digest::HMAC_SHA1->new($key);
	$hmac->add($args->{'file'});
	return $hmac->hexdigest();
}

sub insecureCompare {
	(my $args) = @_;

	for (0 .. length($args->{'hmac'}) - 1) {
		return 0 if (substr($args->{'hmac'}, $_, 1) ne substr($args->{'signature'}, $_, 1));
		usleep($args->{'sleepTime'} * 1000);
	}

	return 1;
}

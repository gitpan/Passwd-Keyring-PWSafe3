#!perl

use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

unless($ENV{PWSAFE_SKIP_TEST}) {
    plan tests => 6;
} else {
    plan skip_all => "Skipped as PWSAFE_SKIP_TEST is set.";
}

use Passwd::Keyring::PWSafe3;

my $DBFILE = File::Spec->catfile($FindBin::Bin, "test.psafe3");

my $APP = "Passwd::PWSafe3::Keyring unit test 08 ";
$APP .= "X" x (256 - length($APP));
my $GROUP = "Passwd::PWSafe3::Keyring unit tests ";
$GROUP .= "X" x (256 - length($GROUP));

my $USER = "A" x 256;
my $PWD =  "B" x 256;
my $REALM = 'C' x 256;

# No lazy_save on purpose
my $ring = Passwd::Keyring::PWSafe3->new(
    app=>$APP, group=>$GROUP,
    file=>$DBFILE,
    master_password=> sub {
        my ($app, $file) = @_;
        is( $app, $APP, "master_password callback got proper app");
        is( $file, $DBFILE, "master_password callback got proper file");
        return "10101010";
    });

ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3',   'new() works with long params' );

$ring->set_password($USER, $PWD, $REALM);

ok( 1, "set_password with long params works" );

ok( $ring->get_password($USER, $REALM) eq $PWD, "get_password with long params works");

ok( $ring->clear_password($USER, $REALM) eq 1, "clear_password with long params works");


#!perl

use strict;
use warnings;
use Test::More;
use File::Spec;
use FindBin;

# TODO: make some non-conditional test, read only one

if($ENV{PWSAFE_FULL_TEST}) {
    plan tests => 7;
} else {
    plan skip_all => "Skipped as runs fairly slowly. Set environment variable PWSAFE_FULL_TEST to execute this test.";
}

#BEGIN {
#    use_ok( 'Passwd::Keyring::PWSafe3' ) || print "Bail out!\n";
#}
use Passwd::Keyring::PWSafe3;

my $DBFILE = File::Spec->catfile($FindBin::Bin, "sampledb", "temporary.psafe3");
my $DBPASS = "3q234q234q234q2345 323442";

my $USER1 = 'John';
my $PASSWORD1 = 'verysecret';
my $USER2 = 'Max';
my $PASSWORD2 = 'notso';
my $REALM = 'some simple realm';

{
    unlink $DBFILE if -f $DBFILE;

    my $ring = Passwd::Keyring::PWSafe3->new(
        file=>$DBFILE, master_password=>$DBPASS, lazy_save=>1);

    ok( defined($ring) && ref $ring eq 'Passwd::Keyring::PWSafe3',   'new() works' );

    $ring->set_password($USER1, $PASSWORD1, $REALM);
    ok( 1, "set_password works" );

    $ring->set_password($USER2, $PASSWORD2, $REALM);
    ok( 1, "set_password works" );

    is( $ring->get_password($USER1, $REALM), $PASSWORD1, "get recovers");
    is( $ring->get_password($USER2, $REALM), $PASSWORD2, "get recovers");
}

{
    # Recreating the ring to make sure file is used
    my $ring = Passwd::Keyring::PWSafe3->new(
        file=>$DBFILE, master_password=>$DBPASS);

    is( $ring->get_password($USER1, $REALM), $PASSWORD1, "get recovers after reload");
    is( $ring->get_password($USER2, $REALM), $PASSWORD2, "get recovers after reload");
}

unlink $DBFILE if -f $DBFILE;


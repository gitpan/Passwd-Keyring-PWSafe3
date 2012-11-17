#!perl -T

use Test::More;

plan tests => 1;

BEGIN {
    use_ok( 'Passwd::Keyring::PWSafe3' ) || print "Bail out!\n";
}

diag( "Testing Passwd::Keyring::PWSafe3 $Passwd::Keyring::PWSafe3::VERSION, Perl $], $^X" );
diag( "***** WARNING *******************************************************" );
diag( "* Those tests go slowly, may take a couple of minutes to complete" );
diag( "* (opening or saving Password Safe file is a slow operation, and it is performed many times)" );
diag( "*********************************************************************" );

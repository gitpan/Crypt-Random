#!/usr/bin/perl -sw
##
##
##
## Copyright (c) 1999, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id$

use lib 'lib';
use lib '../lib';
use Crypt::Random qw(makerandom makerandom_itv);

print "1..2\n";

$r = makerandom ( Size => 512, Verbosity => 1, Strength => 1 );
$y = makerandom ( Size => 512, Verbosity => 1, Strength => 1 );
print "$r, $y\n";
print $r == $y ? "not ok 1" : "ok 1";
print "\n";



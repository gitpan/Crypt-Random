#!/usr/bin/perl -sw
##
##
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id$

use Test;
use Crypt::Random::Generator;
BEGIN { plan tests => 12 };

tests( new Crypt::Random::Generator Strength => 1 );
tests( new Crypt::Random::Generator Strength => 0 );
tests( new Crypt::Random::Generator Provider => 'rand' );

sub tests { 
    my $gen = shift;
    ok($gen->integer (Size => 10) < 1025, 1);
    ok($gen->integer (Upper => 500) < 501, 1);
    ok($gen->integer (Size => 128));
    ok(length($gen->string (Length => 30)), 30);
}

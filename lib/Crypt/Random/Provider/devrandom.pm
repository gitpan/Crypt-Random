#!/usr/bin/perl -sw
##
##
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: devrandom.pm,v 1.2 2001/06/22 18:16:29 vipul Exp $

package Crypt::Random::Provider::devrandom; 
use strict;
use lib qw(/home/vipul/PERL/crypto/random/lib);
use Crypt::Random::Provider::File;
use vars qw(@ISA);
@ISA = qw(Crypt::Random::Provider::File);

sub _defaultsource { return "/dev/random" } 

1;


# Adapted from script by Mark Lawrence (ref. rt.cpan.org #94830)

use strict;
use Digest::SHA3 qw(sha3_224);

package P1;
use vars qw(@ISA);
@ISA = ("Digest::SHA3");

package main;

print "1..1\n";

my $data = 'a';
my $d = P1->new;
print "not " unless $d->add($data)->digest eq sha3_224($data);
print "ok 1\n";

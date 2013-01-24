use strict;
use Digest::SHA3 qw(sha3_224_hex);

my $skip = $] < 5.006 ? 1 : 0;

my $TEMPLATE = $] >= 5.006 ? 'U*' : 'C*';
my $empty_unicode = pack($TEMPLATE, ());
my $ok_unicode    = pack($TEMPLATE, (0..255));
my $wide_unicode  = pack($TEMPLATE, (0..256));

print "1..3\n";

unless ($skip) {
	print "not " unless sha3_224_hex($empty_unicode."abc") eq
		"c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8";
}
print "ok 1", $skip ? " # skip: no Unicode" : "", "\n";

unless ($skip) {
	print "not " unless sha3_224_hex($ok_unicode) eq
		"0ed84ed277ed5eef8317ae0ddf1b7b7277b04b5f632fe86aba291977";
}
print "ok 2", $skip ? " # skip: no Unicode" : "", "\n";

unless ($skip) {
	eval { sha3_224_hex($wide_unicode) };
	print "not " unless $@ =~ /Wide character/;
}
print "ok 3", $skip ? " # skip: no Unicode" : "", "\n";

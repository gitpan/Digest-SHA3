use strict;
use Digest::SHA3 qw(sha3_256_hex);

my @vecs = map { eval } <DATA>;

my $numtests = scalar(@vecs) / 2;
print "1..$numtests\n";

for (1 .. $numtests) {
	my $data = shift @vecs;
	my $digest = shift @vecs;
	print "not " unless sha3_256_hex($data) eq $digest;
	print "ok ", $_, "\n";
}

__DATA__
"abc"
"4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
"45d3b367a6904e6e8d502ee04999a7c27647f91fa845d456525fd352ae3d7371"
"a" x 1000000
"fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96"

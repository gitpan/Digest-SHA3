use strict;
use Digest::SHA3 qw(sha3_224_hex);

# ref. http://www.di-mgt.com.au/sha_testvectors.html

my @vecs = map { eval } <DATA>;

my $numtests = scalar(@vecs) / 2;
print "1..$numtests\n";

for (1 .. $numtests) {
	my $data = shift @vecs;
	my $digest = shift @vecs;
	print "not " unless sha3_224_hex($data) eq $digest;
	print "ok ", $_, "\n";
}

__DATA__
"abc"
"c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8"
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
"e51faa2b4655150b931ee8d700dc202f763ca5f962c529eae55012b6"
"a" x 1000000
"19f9167be2a04c43abd0ed554788101b9c339031acc8e1468531303f"

#!/usr/bin/perl

binmode(STDOUT);
binmode(STDIN);

print "Content-Type: text/plain\r\n";
print "\r\n";

foreach $key (sort (keys (%ENV))) {
    print "$key=$ENV{$key}\n";
}

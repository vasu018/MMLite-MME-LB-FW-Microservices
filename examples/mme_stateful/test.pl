#!/usr/bin/perl -w

my @val = system("ps -aux| grep -i onvm | awk '{print $2}'");
print @val

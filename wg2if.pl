#!/usr/bin/perl

# Convert WireGuard config file to ifconfig/wg commands
#
# Reads the WireGuard config file and outputs equivalent
# ifconfig and wg commands to stdout.
# Usage:
#   wg2if.pl file.conf
#
# See the LICENSE file at the top of the project tree for copyright
# and license details.

use strict;
use warnings;

my $log_enabled = ( -t STDOUT ) ? 1 : 0;

sub logi { return if !$log_enabled; print "[INFO] $_[0]\n"; }
sub logw { return if !$log_enabled; print STDERR "[WARN] $_[0]\n"; }
sub loge { return if !$log_enabled; print STDERR "[ERROR] $_[0]\n"; }

sub die_tool {
    my ($msg) = @_;
    loge($msg);
    exit 1;
}

# -------------------------------------------------
# Argument checks
# -------------------------------------------------

my $file = $ARGV[0] // '';
if ( !$file ) {
    die_tool("usage: $0 file");
}

if ( !-f $file ) {
    die_tool("file $file not found");
}

open my $fh, '<', $file
  or die_tool("Cannot open $file: $!");

# -------------------------------------------------
# State
# -------------------------------------------------

my $interface_mode = 0;
my $peer_mode      = 0;
my $new_peer       = 0;
my $routes         = '';

my $default_gw = get_default_gateway();
logi("Default gateway detected: $default_gw")
  if defined $default_gw;

# -------------------------------------------------
# Main parsing loop
# -------------------------------------------------

while ( my $line = <$fh> ) {
    chomp $line;

    if ( $line =~ /^\[Interface\]/ ) {
        $interface_mode = 1;
        $peer_mode      = 0;
        next;
    }

    if ( $line =~ /^\[Peer\]/ ) {
        if ($interface_mode) {
            print "\n";
            $interface_mode = 0;
        }
        print "\n" if $new_peer;
        $peer_mode = 1;
        $new_peer  = 1;
        next;
    }

    # ---------------- Interface mode ----------------

    if ( $interface_mode && $line =~ /^PrivateKey\s*=\s*(\S+)/ ) {
        print "wgkey $1\n";
    }

    if ( $interface_mode && $line =~ /^PersistentKeepalive\s*=\s*(\S+)/ ) {
        print "wgpka $1\n";
    }

    if ( $interface_mode && $line =~ /^Address\s*=\s*(.+)/ ) {
        my @ips = split /,/, $1;
        for my $ip (@ips) {
            if ( $ip !~ /:/ ) {
                print "inet $ip\n";
                my ($net) = split '/', $ip;
                $routes .= "$net\n!route change default $net\n";
            }
            else {
                print "inet6 $ip\n";
                my ($net) = split '/', $ip;
                $routes .= "$net\n!route add -inet6 default $net\n";
            }
        }
    }

    # ---------------- Peer mode ----------------

    if ( $peer_mode && $line =~ /^PublicKey\s*=\s*(\S+)/ ) {
        print "wgpeer $1 ";
    }

    if ( $peer_mode && $line =~ /^PresharedKey\s*=\s*(\S+)/ ) {
        print "wgpsk $1 ";
    }

    if ( $peer_mode && $line =~ /^Endpoint\s*=\s*(\S+)/ ) {
        my $endpoint = $1;
        $endpoint =~ s/:/ /;
        print "wgendpoint $endpoint ";

        my ($host) = split ' ', $endpoint;
        if ( defined $default_gw ) {
            $routes = "!route add $host $default_gw\n$routes";
        }
        else {
            logw("No default gateway found; skipping route for $host");
        }
    }

    if ( $peer_mode && $line =~ /^AllowedIPs\s*=\s*(.+)/ ) {
        my @ips = split /,/, $1;
        for my $ip (@ips) {
            print "wgaip $ip ";
        }
    }
}

close $fh;

print "\n";
print $routes;

# -------------------------------------------------
# Functions
# -------------------------------------------------

sub get_default_gateway {

    my $output = `route get default 2>/dev/null`;
    if ( $? != 0 ) {
        logw("Failed to execute 'route get default'");
        return undef;
    }

    for my $line ( split /\n/, $output ) {
        if ( $line =~ /^\s*gateway:\s+(\S+)/ ) {
            return $1;
        }
    }

    logw("Default gateway not found in route output");
    return undef;
}

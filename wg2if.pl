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

sub die_tool {
    my ($msg) = @_;
    print "$msg\n";
    exit 1;
}

sub parse_args {
    my $file = $ARGV[0] // '';
    if ( !$file ) {
        die_tool("usage: $0 file");
    }

    if ( !-f $file ) {
        die_tool("file $file not found");
    }

    return $file;
}

sub open_config {
    my ($file) = @_;
    open my $fh, '<', $file
      or die_tool("Cannot open $file: $!");
    return $fh;
}

sub parse_config {
    my ($fh) = @_;

    my $interface_mode = 0;
    my $peer_mode      = 0;
    my $routes         = '';

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
            $peer_mode = 1;
            next;
        }

        if ( $interface_mode && $line =~ /^PrivateKey\s*=\s*(\S+)/ ) {
            print "wgkey $1\n";
        }

        if (   $interface_mode
            && $line =~ /^PersistentKeepalive\s*=\s*(\S+)/ )
        {
            print "wgpka $1\n";
        }

        if ( $interface_mode && $line =~ /^Address\s*=\s*(.+)/ ) {
            my @ips = split /,/, $1;
            for my $ip (@ips) {
                if ( $ip !~ /:/ ) {
                    print "inet $ip\n";
                    my ($net) = split '/', $ip;
                    $routes = "$routes\n!route change default $net";
                }
                else {
                    print "inet6 $ip\n";
                    my ($net) = split '/', $ip;
                    $routes = "$routes\n!route add -inet6 default $net";
                }
            }
        }

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

            my ($host)     = split ' ', $endpoint;
            my $default_gw = get_default_gateway();
            $routes = "!route add $host $default_gw\n$routes";
        }

        if ( $peer_mode && $line =~ /^AllowedIPs\s*=\s*(.+)/ ) {
            my @ips = split /,/, $1;
            for my $ip (@ips) {
                print "wgaip $ip ";
            }
        }
    }

    return $routes;
}

sub print_routes {
    my ($routes) = @_;
    print "\n";
    print $routes;
}

sub main {
    my $file   = parse_args();
    my $fh     = open_config($file);
    my $routes = parse_config($fh);
    close $fh;
    print_routes($routes);
}

# -------------------------------------------------
# Argument checks
# -------------------------------------------------

main();

# -------------------------------------------------
# Functions
# -------------------------------------------------

sub get_default_gateway {
    my $output = `route get default 2>/dev/null`;
    for my $line ( split /\n/, $output ) {
        if ( $line =~ /^\s*gateway:\s*(\S+)/ ) {
            return $1;
        }
    }
    return '';
}

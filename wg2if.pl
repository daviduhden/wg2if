#!/usr/bin/perl

# Convert a WireGuard wg-quick configuration into OpenBSD
# hostname.if(5) directives.
#
# Reads the configuration file, validates its values, and writes
# hostname.if directives and route commands to stdout. It never
# applies the result to the running system.
#
# Usage:
#   wg2if.pl file.conf
#
# See the LICENSE file at the top of the project tree for copyright
# and license details.

use strict;
use warnings;
use Socket qw(AF_INET AF_INET6 inet_ntop inet_pton);

my %warned;
my %gateway_cache;

sub usage {
    return "usage: $0 file";
}

sub die_tool {
    my ($msg) = @_;
    print STDERR "$msg\n";
    exit 1;
}

sub fail {
    my ($line_no, $msg) = @_;
    die_tool("wg2if: line $line_no: $msg");
}

sub warn_once {
    my ($key, $msg) = @_;
    return if $warned{$key}++;
    warn "wg2if: $msg\n";
}

sub trim {
    my ($value) = @_;
    $value =~ s/\A\s+//;
    $value =~ s/\s+\z//;
    return $value;
}

sub parse_args {
    if ( @ARGV == 1
        && ( $ARGV[0] eq '-h' || $ARGV[0] eq '--help' ) )
    {
        print usage(), "\n";
        exit 0;
    }

    if ( @ARGV != 1 ) {
        die_tool(usage());
    }

    my $file = $ARGV[0];
    if ( !-e $file ) {
        die_tool("wg2if: file $file not found");
    }
    if ( !-f $file ) {
        die_tool("wg2if: $file is not a regular file");
    }

    return $file;
}

sub open_config {
    my ($file) = @_;
    open my $fh, '<', $file
      or die_tool("wg2if: cannot open $file: $!");
    return $fh;
}

sub parse_uint {
    my ($value, $min, $max, $line_no, $name) = @_;

    fail($line_no, "invalid $name") unless $value =~ /\A\d+\z/;
    my $number = 0 + $value;
    fail($line_no, "invalid $name") if $number < $min;
    fail($line_no, "invalid $name") if $number > $max;

    return $number;
}

sub validate_key {
    my ($value, $line_no, $name) = @_;

    fail($line_no, "invalid $name")
      unless $value =~ /\A[A-Za-z0-9+\/]{43}=\z/;

    return $value;
}

sub parse_cidr {
    my ($value, $line_no, $name) = @_;

    my ($addr, $prefix) =
      $value =~ /\A([^\/]+)(?:\/(\d{1,3}))?\z/;
    fail($line_no, "invalid $name") unless defined $addr;

    my ($family, $af, $max, $packed);
    $packed = inet_pton(AF_INET, $addr);
    if ( defined $packed ) {
        ( $family, $af, $max ) = ( 'inet', AF_INET, 32 );
    }
    else {
        $packed = inet_pton(AF_INET6, $addr);
        ( $family, $af, $max ) = ( 'inet6', AF_INET6, 128 );
    }
    fail($line_no, "invalid $name address")
      unless defined $packed;

    if ( defined $prefix ) {
        $prefix = 0 + $prefix;
        fail($line_no, "invalid $name prefix")
          if $prefix > $max;
    }
    else {
        $prefix = $max;
    }

    my $canonical = inet_ntop($af, $packed);
    fail($line_no, "invalid $name address")
      unless defined $canonical;

    return ($family, "$canonical/$prefix");
}

sub valid_hostname {
    my ($host) = @_;

    return 0 if length($host) > 253;
    return 0 if $host !~ /\A[A-Za-z0-9.-]+\z/;

    # A dotted numeric name that is not a valid IPv4 address must not
    # be accepted as a hostname.
    return 0 if $host =~ /\A[0-9.]+\z/;

    for my $label ( split /\./, $host, -1 ) {
        return 0 if $label eq '';
        return 0 if length($label) > 63;
        return 0 if $label =~ /\A-|-\z/;
    }

    return 1;
}

sub parse_endpoint {
    my ($value, $line_no) = @_;

    my ($host, $port, $family);
    if ( $value =~ /\A\[([^\]]+)\]:(\d{1,5})\z/ ) {
        $host   = $1;
        $port   = $2;
        $family = 'inet6';

        my $packed = inet_pton(AF_INET6, $host);
        fail($line_no, 'invalid Endpoint address')
          unless defined $packed;
        $host = inet_ntop(AF_INET6, $packed);
        fail($line_no, 'invalid Endpoint address')
          unless defined $host;
    }
    elsif ( $value =~ /\A([^:]+):(\d{1,5})\z/ ) {
        $host = $1;
        $port = $2;

        my $packed = inet_pton(AF_INET, $host);
        if ( defined $packed ) {
            $host   = inet_ntop(AF_INET, $packed);
            $family = 'inet';
            fail($line_no, 'invalid Endpoint address')
              unless defined $host;
        }
        elsif ( valid_hostname($host) ) {
            $family = 'hostname';
        }
        else {
            fail($line_no, 'invalid Endpoint host');
        }
    }
    else {
        fail($line_no,
          'invalid Endpoint; expected host:port or [IPv6]:port');
    }

    $port = parse_uint($port, 1, 65535, $line_no, 'Endpoint port');

    return ($host, $port, $family);
}

sub push_unique_addr {
    my ($list, $family, $cidr) = @_;

    for my $item (@$list) {
        return if $item->{family} eq $family
          && $item->{cidr} eq $cidr;
    }

    push @$list, { family => $family, cidr => $cidr };
}

sub parse_interface_key {
    my ($cfg, $key, $value, $line_no) = @_;
    my $if = $cfg->{interface};

    if ( $key eq 'privatekey' ) {
        fail($line_no, 'duplicate PrivateKey')
          if defined $if->{private_key};
        $if->{private_key} =
          validate_key($value, $line_no, 'PrivateKey');
    }
    elsif ( $key eq 'address' ) {
        for my $item ( split /,/, $value, -1 ) {
            $item = trim($item);
            fail($line_no, 'empty Address entry')
              if $item eq '';
            my ($family, $cidr) =
              parse_cidr($item, $line_no, 'Address');
            push_unique_addr($if->{addresses}, $family, $cidr);
        }
    }
    elsif ( $key eq 'persistentkeepalive' ) {
        $if->{keepalive} =
          parse_uint($value, 0, 65535, $line_no,
            'PersistentKeepalive');
    }
    elsif ( $key eq 'listenport' ) {
        $if->{listen_port} =
          parse_uint($value, 1, 65535, $line_no, 'ListenPort');
    }
    elsif ( $key eq 'mtu' ) {
        $if->{mtu} =
          parse_uint($value, 576, 65535, $line_no, 'MTU');
    }
    elsif ( $key eq 'dns' ) {
        warn_once('dns',
          'DNS is not modified; configure resolvd or ' .
          '/etc/resolv.conf manually');
    }
    else {
        warn_once("unsupported-interface-$key",
          "unsupported directive $key in [Interface]; ignored");
    }
}

sub parse_peer_key {
    my ($peer, $key, $value, $line_no) = @_;

    if ( $key eq 'publickey' ) {
        fail($line_no, 'duplicate PublicKey')
          if defined $peer->{public_key};
        $peer->{public_key} =
          validate_key($value, $line_no, 'PublicKey');
    }
    elsif ( $key eq 'presharedkey' ) {
        fail($line_no, 'duplicate PresharedKey')
          if defined $peer->{preshared_key};
        $peer->{preshared_key} =
          validate_key($value, $line_no, 'PresharedKey');
    }
    elsif ( $key eq 'endpoint' ) {
        fail($line_no, 'duplicate Endpoint')
          if defined $peer->{endpoint_host};
        my ($host, $port, $family) =
          parse_endpoint($value, $line_no);
        $peer->{endpoint_host}   = $host;
        $peer->{endpoint_port}   = $port;
        $peer->{endpoint_family} = $family;
    }
    elsif ( $key eq 'allowedips' ) {
        for my $item ( split /,/, $value, -1 ) {
            $item = trim($item);
            fail($line_no, 'empty AllowedIPs entry')
              if $item eq '';
            my ($family, $cidr) =
              parse_cidr($item, $line_no, 'AllowedIPs');
            push_unique_addr($peer->{allowed}, $family, $cidr);
        }
    }
    elsif ( $key eq 'persistentkeepalive' ) {
        $peer->{keepalive} =
          parse_uint($value, 0, 65535, $line_no,
            'PersistentKeepalive');
    }
    else {
        warn_once("unsupported-peer-$key",
          "unsupported directive $key in [Peer]; ignored");
    }
}

sub push_peer {
    my ($cfg, $peer, $line_no) = @_;
    return unless defined $peer;

    fail($line_no, 'peer has no PublicKey')
      unless defined $peer->{public_key};

    push @{ $cfg->{peers} }, $peer;
}

sub parse_config {
    my ($fh) = @_;

    my $cfg = {
        seen_interface => 0,
        interface      => { addresses => [] },
        peers          => [],
    };
    my $section = '';
    my $peer;
    my $line_no = 0;

    while ( my $line = <$fh> ) {
        $line_no++;
        $line =~ s/\r?\n\z//;
        $line =~ s/#.*\z//;
        $line = trim($line);
        next if $line eq '';

        if ( $line =~ /\A\[\s*(Interface|Peer)\s*\]\z/i ) {
            my $name = lc $1;
            if ( $name eq 'interface' ) {
                fail($line_no, 'duplicate [Interface] section')
                  if $cfg->{seen_interface};
                $cfg->{seen_interface} = 1;
                $section = 'interface';
                $peer    = undef;
            }
            else {
                fail($line_no,
                  '[Peer] section before [Interface]')
                  unless $cfg->{seen_interface};
                push_peer($cfg, $peer, $line_no);
                $peer = { allowed => [] };
                $section = 'peer';
            }
            next;
        }

        if ( $line =~ /\A\[/ ) {
            fail($line_no, 'unsupported section header');
        }

        my ($key, $value) =
          $line =~ /\A([A-Za-z][A-Za-z0-9]*)\s*=\s*(.*)\z/;
        fail($line_no, 'expected key = value')
          unless defined $key;

        $key   = lc $key;
        $value = trim($value);
        fail($line_no, "empty value for $key") if $value eq '';

        if ( $section eq 'interface' ) {
            parse_interface_key($cfg, $key, $value, $line_no);
        }
        elsif ( $section eq 'peer' ) {
            parse_peer_key($peer, $key, $value, $line_no);
        }
        else {
            fail($line_no, 'directive outside a section');
        }
    }

    die_tool('wg2if: missing [Interface] section')
      unless $cfg->{seen_interface};
    push_peer($cfg, $peer, $line_no);
    die_tool('wg2if: missing PrivateKey in [Interface]')
      unless defined $cfg->{interface}{private_key};

    if ( defined $cfg->{interface}{keepalive}
        && !@{ $cfg->{peers} } )
    {
        warn_once('keepalive-no-peer',
          'PersistentKeepalive set in [Interface] but no peers');
    }

    return $cfg;
}

sub add_route {
    my ($routes, $seen, $route) = @_;
    return if $seen->{$route}++;
    push @$routes, $route;
}

sub valid_gateway {
    my ($gateway, $family) = @_;

    my ($addr, $scope) =
      $gateway =~ /\A([0-9A-Fa-f:.]+)(?:%([A-Za-z0-9._-]+))?\z/;
    return 0 unless defined $addr;
    return 0 if $family eq 'inet' && defined $scope;

    my $af = $family eq 'inet6' ? AF_INET6 : AF_INET;
    return 0 unless defined inet_pton($af, $addr);

    return 1;
}

sub run_route {
    my (@args) = @_;

    my $pid = open my $fh, '-|';
    return '' unless defined $pid;

    if ( !$pid ) {
        open STDERR, '>', '/dev/null';
        exec { '/sbin/route' } '/sbin/route', @args;
        exit 127;
    }

    my $output = '';
    $output .= $_ while <$fh>;
    close $fh;

    return $output;
}

sub get_default_gateway {
    my ($family) = @_;

    return $gateway_cache{$family}
      if exists $gateway_cache{$family};

    my @candidate_args = $family eq 'inet6'
      ? ( [ '-n', 'get', '-inet6', 'default' ],
          [ '-n', 'get', 'default', '-inet6' ] )
      : ( [ '-n', 'get', 'default' ] );

    for my $args (@candidate_args) {
        my $output = run_route(@$args);
        for my $line ( split /\n/, $output ) {
            next unless $line =~ /^\s*gateway:\s*(\S+)/;
            my $gateway = trim($1);
            next unless valid_gateway($gateway, $family);
            $gateway_cache{$family} = $gateway;
            return $gateway;
        }
    }

    $gateway_cache{$family} = '';
    return '';
}

sub render_config {
    my ($cfg) = @_;
    my $if = $cfg->{interface};

    print "wgkey $if->{private_key}\n";
    print "wgport $if->{listen_port}\n"
      if defined $if->{listen_port};
    print "mtu $if->{mtu}\n" if defined $if->{mtu};

    for my $addr ( @{ $if->{addresses} } ) {
        print "$addr->{family} $addr->{cidr}\n";
    }

    for my $peer ( @{ $cfg->{peers} } ) {
        my $line = "wgpeer $peer->{public_key}";
        $line .= " wgpsk $peer->{preshared_key}"
          if defined $peer->{preshared_key};

        if ( defined $peer->{endpoint_host} ) {
            $line .= " wgendpoint $peer->{endpoint_host}";
            $line .= " $peer->{endpoint_port}";
        }

        for my $item ( @{ $peer->{allowed} } ) {
            $line .= " wgaip $item->{cidr}";
        }

        my $keepalive = defined $peer->{keepalive}
          ? $peer->{keepalive}
          : $if->{keepalive};
        $line .= " wgpka $keepalive" if defined $keepalive;

        print "$line\n";
    }

    print "up\n";

    my @routes;
    my %seen;

    for my $peer ( @{ $cfg->{peers} } ) {
        next unless defined $peer->{endpoint_host};

        my $family = $peer->{endpoint_family};
        my $lookup = $family eq 'inet6' ? 'inet6' : 'inet';
        my $gateway = get_default_gateway($lookup);
        my $label = $lookup eq 'inet6' ? 'IPv6' : 'IPv4';
        if ( !$gateway ) {
            warn_once("gateway-$lookup",
              "no $label default route found; " .
              'endpoint routes cannot be generated');
            next;
        }

        my $flag = $family eq 'inet6' ? '-inet6 ' : '';
        my $host = $peer->{endpoint_host};
        add_route(\@routes, \%seen,
          "!route add $flag$host $gateway");
    }

    for my $peer ( @{ $cfg->{peers} } ) {
        for my $item ( @{ $peer->{allowed} } ) {
            my $flag =
              $item->{family} eq 'inet6' ? '-inet6 ' : '';
            my $cidr = $item->{cidr};
            add_route(\@routes, \%seen,
              "!route add $flag$cidr -iface \$if");
        }
    }

    if (@routes) {
        print "\n";
        for my $route (@routes) {
            print "$route\n";
        }
    }
}

sub main {
    my $file = parse_args();
    my $fh   = open_config($file);
    my $cfg  = parse_config($fh);
    close $fh
      or die_tool("wg2if: cannot read $file: $!");
    render_config($cfg);
}

main();

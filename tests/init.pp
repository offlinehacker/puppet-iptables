node default {
    package { "iptables-persistent":
        ensure => "installed"
    }

    class {"iptables::globals":
        iptables_path => "/etc/iptables/rules.v4",
        ip6tables_path => "/etc/iptables/rules.v6"
    }

    iptables::chain::filter { ["INPUT", "OUTPUT", "FORWARD"]:
        policy => "DROP"
    }

    # Chain used for port forwading rules
    iptables::chain::filter { ["port_forward"] }

    ip6tables::chain::filter { ["INPUT", "OUTPUT", "FORWARD"]:
        policy => "DROP"
    }

    # Chain used for port forwading rules
    ip6tables::chain::filter { ["port_forward"] }
   
    iptables::chain::nat { ["PREROUTING", "POSTROUTING", "INPUT", "OUTPUT"]:
        policy => "ACCEPT"
    }

    # Chain used for port forwading rules
    iptables::chain::nat { ["port_forward"] }

    # Helper  
    define port_forward($interface, $proto, $ip, $ip6, $port) {
        iptables::nat { "$name":
            chain => "port_forward",
            changes => [
                    "set protocol $proto",
                    "set input $interface",
                    "set match[. = '$proto'] $proto",
                    "set dport $port",
                    "set jump DNAT",
                    "set to $ip",
            ],
        }

        iptables::filter { "$name":
            chain => "port_forward",
            changes => [
                    "set protocol $proto",
                    "set in-interface $interface",
                    "set destination $ip",
                    "set match[. = '$proto'] $proto",
                    "set dport $port",
                    "set match [ . = 'state'] state",
                    "set state 'NEW,ESTABLISHED,RELATED'"
                    "set jump ACCEPT",
            ],
        }

        ip6tables::filter { "$name":
            chain => "port_forward",
            changes => [
                    "set protocol tcp",
                    "set in-interface $interface",
                    "set destination $ip6",
                    "set match[. = 'tcp'] tcp",
                    "set dport $port",
                    "set match [ . = 'state'] state",
                    "set state 'NEW,ESTABLISHED,RELATED'"
                    "set jump ACCEPT",
            ],
        }
    }

    port_forward { "port_forward_65500":
        $interface => "eth0",
        $ip => "10.2.0.10:22",
        $ip6 => "2001:db8:0:2::10",
        $port => 65500
    }

    port_forward { "port_forward_80":
        $interface => "eth0",
        $ip => "10.2.0.10",
        $ip6 => "2001:db8:0:2::10",
        $port => 80
    }

    port_forward { "port_forward_443":
        $interface => "eth0",
        $ip => "10.2.0.10",
        $ip6 => "2001:db8:0:2::10",
        $port => 443
    }

    iptables::filter { "port_forward":
        chain => "FORWARD",
        changes => [
                "set in-interface eth0",
                "set jump port_forward",
        ],
    }

    iptables::nat { "port_forward":
        chain => "PREROUTING",
        changes => [
                "set in-interface eth0",
                "set jump port_forward",
        ],
    }

    ip6tables::filter { "port_forward":
        chain => "FORWARD",
        changes => [
                "set in-interface eth0",
                "set jump port_forward",
        ],
    }

    # Enable masquerading for server behind nat
    iptables::nat { "masquerade":
        chain => "POSTROUTING",
        changes => [
                "set out-interface eth0",
                "set jump MASQUERADE",
        ],
    }

    # Enable related and establised connections to outside
    iptables::filter { "accept_established":
        chain => "FORWARD",
        changes => [
                "set out-interface eth0",
                "set match [ . = 'state'] state",
                "set state 'ESTABLISHED,RELATED'",
                "set jump ACCEPT",
        ],
        require => [Iptables::Filter["port_forward"]]
    }

    # Enable related and establised connections to outside
    ip6tables::filter { "accept_established":
        chain => "FORWARD",
        changes => [
                "set out-interface eth0",
                "set match [ . = 'state'] state",
                "set state 'ESTABLISHED,RELATED'",
                "set jump ACCEPT",
        ],
        require => [Ip6tables::Filter["port_forward"]]
    }
}

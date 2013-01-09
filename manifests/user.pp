define iptables::mark_external_traffic($mark) {
    iptables::chain::mangle { "mark_external": }

    $mark_external = {
        'mark_external_OUTPUT' => {
                chain  => 'OUTPUT',
                changes  => "
                    set match[ . = 'state'] state
                    set state NEW
                    set jump mark_external
                ",
        },
        'mark_external_PREROUTING' => {
                chain  => 'PREROUTING',
                changes  => "
                    set match[ . = 'state'] state
                    set state NEW
                    set jump mark_external
                ",
        },
        'mark_external_192.168.0.0/16' => {
                chain  => 'mark_external',
                changes  => "
                    set destination 192.168.0.0/16
                    set jump RETURN
                ",
        },
        'mark_external_10.0.0.0/8' => {
                chain  => 'mark_external',
                changes  => "
                    set destination 10.0.0.0/8
                    set jump RETURN
                ",
                require => [Iptables::Mangle['mark_external_192.168.0.0/16']]
        },
        'mark_external_172.16.0.0/12' => {
                chain  => 'mark_external',
                changes  => "
                    set destination 172.16.0.0/12
                    set jump RETURN
                ",
                require => [Iptables::Mangle['mark_external_10.0.0.0/8']]
        },
        'mark_external' => {
                chain  => 'mark_external',
                changes  => "
                    set jump MARK
                    set set-mark $mark
                ",
                require => [Iptables::Mangle['mark_external_172.16.0.0/12']]
        },
        'mark_external_connmark' => {
                chain  => 'mark_external',
                changes  => "
                    set jump CONNMARK
                    set save-mark 1
                ",
                require => [Iptables::Mangle['mark_external']]
        }
    }

    create_resources("Iptables::Mangle", $mark_external)
}

# Helper to create prot forwarding 
define port_forward($interface, $proto = "tcp", $ip, $ip6, $port) {
    iptables::nat { "$name":
        chain => "port_forward",
        changes => [
                "set protocol $proto",
                "set in-interface $interface",
                "set match[ . = '$proto'] $proto",
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
                "set match[ . = '$proto'] $proto",
                "set dport $port",
                "set match[ . = 'state'] state",
                "set state 'NEW,ESTABLISHED,RELATED'",
                "set jump ACCEPT",
        ],
    }

    ip6tables::filter { "$name":
        chain => "port_forward",
        changes => [
                "set protocol tcp",
                "set in-interface $interface",
                "set destination $ip6",
                "set match[ . = '$proto'] $proto",
                "set dport $port",
                "set match[ . = 'state'] state",
                "set state 'NEW,ESTABLISHED,RELATED'",
                "set jump ACCEPT",
        ],
    }
}

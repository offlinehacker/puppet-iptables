# Puppet iptables/ip6tables module using augeas for rule managment

Cross platform puppet iptables/ip6tables module using augeas for 
rule managment

What does this mean?

* Is easy and straightforward
* And advanced at the same time
* it will preserve all current or later included rules until they 
  don't break the iptables functionality you describe from puppet.

This module should cover all use cases and, because it's directly
using augeas it let's user write rules in augeas format and at the
same time keep it simple. Also rule order can simply be preserved.

## Types

This module provides several types to make configuring iptables 
easier.

They are splitted in two layers of abstractions:

* Base iptables types
* Helper iptables types

### Base iptables types

Base types are basic types that manage iptables/ip6tables on
the same way. **It is advised not to use them, but usage of helper
types is preffered**.

If you must use them, because helper types does not fit your needs,
first create config with specified location of your ip table:

    iptables::config {"my_iptables_config":
        path => /path/to/my/iptables
    }

Now you can define several tables you wish to use:

    iptables::table {"my_nat_table":
        config => Iptable::Config["my_iptables_config"],
        table => "nat"
    }

    iptables::table {"my_filter_table":
        config => Iptable::Config["my_iptables_config"],
        table => "filter"
    }

    iptables::table {"my_mangle_table":
        config => Iptable::Config["my_iptables_config"],
        table => "mangle"
    }

Now define your chains, where you will put iptable rules:

    iptables::chain { "my_input_filter_chain":
        chain => "INPUT",
        table => Iptables::Table["my_filter_table"],
        policy => "DROP"
    }

    iptables::chain { "my_output_filter_chain":
        chain => "OUTPUT",
        table => Iptables::Table["my_filter_table"],
        policy => "DROP"
    }

    iptables::chain { "my_prerouting_nat_chain":
        chain => "PREROUTING",
        table => Iptables::Table["my_nat_table"],
        policy => "ACCEPT"
    }

    iptables::chain { "my_postrouting_nat_chain":
        chain => "POSTROUTING",
        table => Iptables::Table["my_nat_table"],
        policy => "ACCEPT"
    }

Great you are ready to create new rules:

    # Enable DNAT for 192.168.2.10:80
    iptables::rule { "forward_port_80_nat":
        table => Iptables::Table["my_nat_table"],
        chain => "PREROUTING",
        changes => [
                "set protocol tcp",
                "set input eth0",
                "set match[. = 'tcp'] tcp",
                "set dport 80",
                "set jump DNAT",
                "set to 192.168.1.10",
        ],
    }

    # Accept forwarding connection on port 80
    iptables::rule { "forward_port_80_filter":
        table => Iptables::Table["my_filter_table"],
        chain => "FORWARD",
        changes => [
                "set protocol tcp",
                "set in-interface eth0",
                "set destination 192.168.1.10",
                "set match[. = 'tcp'] tcp",
                "set dport 80",
                "set match [ . = 'state'] state",
                "set state 'NEW,ESTABLISHED,RELATED'"
                "set jump ACCEPT",
        ],
    }

    # Enable masquerading for server behind nat
    iptables::rule { "masquerade":
        table => Iptables::Table["my_nat_table"],
        chain => "POSTROUTING",
        changes => [
                "set out-interface eth0",
                "set jump MASQUERADE",
        ],
    }

### Helper iptables types

Because usage of base iptables types if slow, i created some
helper types to make writing iptables more sane. All tables are
already there for you and you can easily rewrite code above as
following:

    class {"iptables::globals":
        iptables_path => "/path/to/my/iptables",
    }

    iptables::chain::filter { ["INPUT", "OUTPUT"]:
        policy => "DROP"
    }

    iptables::chain::nat { ["PREROUTING", "POSTROUTING"]:
        policy => "ACCEPT"
    }

    # Enable DNAT for 192.168.2.10:80
    iptables::nat { "forward_port_80":
        chain => "PREROUTING",
        changes => [
                "set protocol tcp",
                "set input eth0",
                "set match[. = 'tcp'] tcp",
                "set dport 80",
                "set jump DNAT",
                "set to 192.168.1.10",
        ],
    }

    # Accept forwarding connection on port 80
    iptables::filter { "forward_port_80":
        chain => "FORWARD",
        changes => [
                "set protocol tcp",
                "set in-interface eth0",
                "set destination 192.168.1.10",
                "set match[. = 'tcp'] tcp",
                "set dport 80",
                "set match [ . = 'state'] state",
                "set state 'NEW,ESTABLISHED,RELATED'"
                "set jump ACCEPT",
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

Pretty straightforward huh? 

Well there are also other helper types defined, especially i didn't 
mention ipv6 helper equialents, but you can look them up in helpers.pp file.

## Example

This is more advanced example of how to use this module in a sane way.

    package { "iptables-persistent":
        ensure => "installed"
    }

    class {"iptables::globals":
        iptables_path => "/etc/iptables/rules.v4",
        ip6tables_path => "/etc/iptables/rules.v6"
    }

    iptables::chain::filter { ["INPUT", "OUTPUT", "FORWARD"]:
        policy => "ACCEPT"
    }

    # Chain used for port forwading rules
    iptables::chain::filter { ["port_forward"]:
        policy => "-"
    }

    ip6tables::chain::filter { ["INPUT", "OUTPUT", "FORWARD"]:
        policy => "ACCEPT"
    }

    # Chain used for port forwading rules
    ip6tables::chain::filter { ["port_forward"]:
        policy => "-"
    }
   
    iptables::chain::nat { ["PREROUTING", "POSTROUTING", "INPUT", "OUTPUT"]:
        policy => "ACCEPT"
    }

    # Chain used for port forwading rules
    iptables::chain::nat { ["port_forward"]:
        policy => "-"
    }

    # Check user.pp for defintion
    port_forward { "port_forward_65500":
        interface => "eth1",
        ip => "10.2.0.10",
        ip6 => "2001:db8:0:2::10",
        port => "22"
    }

    # Check user.pp for defintion
    port_forward { "port_forward_80":
        interface => "eth1",
        ip => "10.2.0.10",
        ip6 => "2001:db8:0:2::10",
        port => "80"
    }

    # Check user.pp for defintion
    port_forward { "port_forward_443":
        interface => "eth1",
        ip => "10.2.0.10",
        ip6 => "2001:db8:0:2::10",
        port => "443"
    }

    iptables::filter { "port_forward":
        chain => "FORWARD",
        changes => [
                "set in-interface eth1",
                "set jump port_forward",
        ],
    }

    iptables::nat { "port_forward":
        chain => "PREROUTING",
        changes => [
                "set in-interface eth1",
                "set jump port_forward",
        ],
    }

    ip6tables::filter { "port_forward":
        chain => "FORWARD",
        changes => [
                "set in-interface eth1",
                "set jump port_forward",
        ],
    }

    # Enable masquerading for server behind nat
    iptables::nat { "masquerade":
        chain => "POSTROUTING",
        changes => [
                "set out-interface eth1",
                "set jump MASQUERADE",
        ],
    }

    # Enable related and establised connections to outside
    iptables::filter { "accept_established":
        chain => "FORWARD",
        changes => [
                "set out-interface eth1",
                "set match[ . = 'state'] state",
                "set state 'ESTABLISHED,RELATED'",
                "set jump ACCEPT",
        ],
        require => [Iptables::Filter["port_forward"]]
    }

    # Enable related and establised connections to outside
    ip6tables::filter { "accept_established":
        chain => "FORWARD",
        changes => [
                "set out-interface eth1",
                "set match[ . = 'state'] state",
                "set state 'ESTABLISHED,RELATED'",
                "set jump ACCEPT",
        ],
        require => [Ip6tables::Filter["port_forward"]]
    }

## Contributions welcome!

Please contribute your code as pull requests if you add or fix code.
I will try to merge or comment as soon as possible. Thanks! :)

## License

[Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0.html)

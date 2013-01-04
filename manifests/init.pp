import "base"

class iptables::globals($iptables_path = "/etc/iptables-save", 
                        $ip6tables_path = "/etc/iptables-save") {
    # Global configs
    iptables::config { "iptables.globals.config":
        path => $iptables_path
    }

    iptables::config { "ip6tables.globals.config":
        path => $ip6tables_path
    }


    # Global tables
    iptables::table { "iptables.globals.table.filter":
        table => "filter",
        config => Iptables::Config["iptables.globals.config"]
    }

    iptables::table { "iptables.globals.table.nat":
        table => "nat",
        config => Iptables::Config["iptables.globals.config"]
    }

    iptables::table { "iptables.globals.table.mangle":
        table => "mangle",
        config => Iptables::Config["iptables.globals.config"]
    }

    # Global ipv6 tables
    iptables::table { "ip6tables.globals.table.filter":
        table => "filter",
        config => Iptables::Config["ip6tables.globals.config"]
    }

    iptables::table { "ip6tables.globals.table.mangle":
        table => "mangle",
        config => Iptables::Config["ip6tables.globals.config"]
    }
}

# Helpers for defining iptables chains
define iptables::chain::filter($policy) {
    iptables::chain { "iptables.chain.filter.$name":
        table => Iptables::Table["iptables.globals.table.filter"],
        policy => $policy,
        chain => $name
    }
}

define iptables::chain::nat($policy) {
    iptables::chain { "iptables.chain.nat.$name":
        table => Iptables::Table["iptables.globals.table.nat"],
        policy => $policy,
        chain => $name
    }
}

define iptables::chain::mangle($policy) {
    iptables::chain { "iptables.chain.mangle.$name":
        table => Iptables::Table["iptables.globals.table.mangle"],
        policy => $policy,
        chain => $name
    }
}

define ip6tables::chain::filter($policy) {
    iptables::chain { "ip6tables.chain.filter.$name":
        table => Iptables::Table["ip6tables.globals.table.filter"],
        policy => $policy,
        chain => $name
    }
}

define ip6tables::chain::mangle($policy) {
    iptables::chain { "ip6tables.chain.mangle.$name":
        table => Iptables::Table["ip6tables.globals.table.mangle"],
        policy => $policy,
        chain => $name
    }
}


# Helpers for defining iptables rules
define iptables::filter($chain, $changes, $remove_duplicates = true) {
    iptables::rule { "$name":
        table => Iptables::Table["iptables.globals.table.filter"],
        chain => $chain,
        changes => $changes,
        remove_duplicates => $remove_duplicates,
        require => $require
    }
}

define iptables::nat($chain, $changes, $remove_duplicates = true) {
    iptables::rule { "$name":
        table => Iptables::Table["iptables.globals.table.nat"],
        chain => $chain,
        changes => $changes,
        remove_duplicates => $remove_duplicates,
        require => $require
    }
}

define iptables::mangle($chain, $changes, $remove_duplicates = true) {
    iptables::rule { "$name":
        table => Iptables::Table["iptables.globals.table.mangle"],
        chain => $chain,
        changes => $changes,
        remove_duplicates => $remove_duplicates,
        require => $require
    }
}

define ip6tables::filter($chain, $changes, $remove_duplicates = true) {
    ip6tables::rule { "$name":
        table => Iptables::Table["ip6tables.globals.table.filter"],
        chain => $chain,
        changes => $changes,
        remove_duplicates => $remove_duplicates,
        require => $require
    }
}

define ip6tables::mangle($chain, $changes, $remove_duplicates = true) {
    ip6tables::rule { "$name":
        table => Iptables::Table["ip6tables.globals.table.nat"],
        chain => $chain,
        changes => $changes,
        remove_duplicates => $remove_duplicates,
        require => $require
    }
}

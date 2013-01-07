define iptables::config($path) { }

define iptables::table($table = $name, $config) {
    $path = getparam($config, "path")

    augeas { "$name":
        context => "/files$path",
        changes => ["set table[ . = '$table'] $table"],
        lens => 'Iptables.lns',
        incl => $path
    } 
}

define iptables::chain($chain = $name, $table, $policy = undef, $config = getparam($table, "config")) {
    $path = getparam($config, "path")
    $table_name = getparam($table, "table")

    if $policy {
        $changes =  ["set chain[ . = '$chain'] $chain",
                     "set chain[ . = '$chain']/policy $policy"]
    } else {
        $changes =  ["set chain[ . = '$chain'] $chain"]
    }

    # Add chain
    augeas { "iptables.chain.$table.$chain.add":
        context => "/files$path/table[ . = '$table_name']",
        changes => $changes,
        lens => 'Iptables.lns',
        incl => $path
    }
}

define ip6tables::chain($table, $policy) {
    iptables::chain { "ip6tables.chain.$name":
        table => $table,
        policy => $policy,
        chain => $name
    }
}

define iptables::rule($rule_name = $name, $table, $chain, $changes, 
                      $remove_duplicates = true, 
                      $config = getparam($table, "config")) {
    $path = getparam($config, "path")
    $table_name = getparam($table, "table")

    if !is_string($chain) {
        $chain_name = inline_template("<%= chain.title %>")
    } else {
        $chain_name = $chain
    }
    
    # Construct ipt rules conditionals
    if $require {
        $req_rule = "self::append[ comment = '%s']"
        $req_rule_sib = "preceding-sibling::*[self::append[ comment = '%s']]"

        $req_q = inline_template(join(
            ["<% @require.each_with_index do |k, i| -%>",
             "<%= \"$req_rule\" % k.title %><% if i<k.length-1 -%> and <% end -%>",
             "<% end -%>"]))
        $req_q_sib = inline_template(join(
            ["<% @require.each_with_index do |k, i| -%>",
             "<%= \"$req_rule_sib\" % k.title %><% if i<k.length-1 -%> and <% end -%>",
             "<% end -%>"]))
    }

    if $require { # Append after first matching rule
        $q  = "append[comment='$rule_name' and $req_q_sib]"
        $ins_q = "append[$req_q]"
        $ins_q_sib = "append[$req_q_sib]"
        notice("Ins query is $ins_q and query is $q")

        augeas { "iptables.rule.$rule_name.add":
            context => "/files$path/table[ . = '$table_name']",
            changes => ["ins append after $ins_q[1]",
                        "set $ins_q_sib[1] $chain_name",
                        "set $ins_q_sib[1]/match[ . = 'comment'] comment",
                        "set $ins_q_sib[1]/comment $rule_name"],
            onlyif => "match $q size==0",
            lens => 'Iptables.lns',
            incl => $path
        }
    } else { # Append at the end of chain
        $q = "append[comment='$rule_name']"
        $ins_q = "append[ . = '$rule_name']"
        notice("Ins query is $ins_q and query is $q")

        augeas { "iptables.rule.$rule_name.add":
            context => "/files$path/table[ . = '$table_name']",
            changes => ["set $ins_q $rule_name",
                        "set $ins_q/match[last()+1] comment",
                        "set $ins_q/comment $rule_name",
                        "set $ins_q $chain_name"],
            onlyif => "match $q size==0",
            lens => 'Iptables.lns',
            incl => $path
        }
    }

    if $remove_duplicates {
        augeas { "iptables.rule.$rule_name.rm":
            context => "/files$path/table[ . = '$table_name']",
            changes => ["rm append[ comment = '$rule_name' and preceding-sibling::$q]",
                        "rm append[ comment = '$rule_name' and following-sibling::$q]"],
            require => Augeas["iptables.rule.$rule_name.add"],
            lens => 'Iptables.lns',
            incl => $path
        }
    }

    # Set contents of the rule
    augeas { "iptables.rule.$rule_name":
        context => "/files$path/table[ . = '$table_name']/$q",
        changes => $changes,
        require => Augeas["iptables.rule.$rule_name.add"],
        lens => 'Iptables.lns',
        incl => $path
    }
}

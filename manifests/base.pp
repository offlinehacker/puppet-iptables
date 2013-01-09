define iptables::config($path, $flush = true) {
    if $flush {
        augeas { "$path.flush":
            context => "/files$path",
            changes => "rm table/*",
            lens => 'Iptables.lns',
            incl => $path
        }
    }
}

define iptables::table($table = $name, $config) {
    $path = getparam($config, "path")

    augeas { "$name.edit":
        context => "/files$path",
        changes => "set table[ . = '$table'] $table",
        lens => 'Iptables.lns',
        incl => $path
    } 
}

define iptables::chain($chain = $name, $table, $policy = undef, $config = getparam($table, "config")) {
    $path = getparam($config, "path")
    $table_name = getparam($table, "table")

    # Add chain
    augeas { "iptables.chain.$table.$chain.add":
        context => "/files$path/table[ . = '$table_name']",
        changes => "
            set #comment[ . = 'at_least_one_element'] 'at_least_one_element'
            ins chain before *[1]
            set chain[1] $chain
            set chain[1]/policy $policy
            rm #comment[ . = 'at_least_one_element']
        ",
        lens => 'Iptables.lns',
        incl => $path,
        onlyif => "match chain[ . = '$chain'] size==0"
    }

    # Edit chain policy
    augeas { "iptables.chain.$table.$chain.edit":
        context => "/files$path/table[ . = '$table_name']",
        changes => "set chain[ . = '$chain']/policy $policy",
        lens => 'Iptables.lns',
        incl => $path,
        require => Augeas["iptables.chain.$table.$chain.add"]
    }
}

define iptables::rule($rule = $name, $table, $chain, $changes, 
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
        $q  = "append[comment='$rule' and $req_q_sib]"
        $ins_q = "append[$req_q]"
        $ins_q_sib = "append[$req_q_sib]"
        notice("Ins query is $ins_q and query is $q")

        augeas { "iptables.rule.[$name].add":
            context => "/files$path/table[ . = '$table_name']",
            changes => "
                ins append after $ins_q[1]
                set $ins_q_sib[1] $chain_name
                set $ins_q_sib[1]/match[ . = 'comment'] comment
                set $ins_q_sib[1]/comment $rule
            ",
            onlyif => "match $q size==0",
            lens => 'Iptables.lns',
            incl => $path
        }
    } else { # Append at the end of chain
        $q = "append[comment='$rule']"
        $ins_q = "append[ . = '${rule}_temp']"
        notice("Ins query is $ins_q and query is $q")

        augeas { "iptables.rule.[$name].add":
            context => "/files$path/table[ . = '$table_name']",
            changes => "
                set $ins_q ${rule}_temp
                set $ins_q/match[last()+1] comment
                set $ins_q/comment $rule
                set $ins_q $chain_name
            ",
            onlyif => "match $q size==0",
            lens => 'Iptables.lns',
            incl => $path
        }
    }

    if $remove_duplicates {
        augeas { "iptables.rule.[$name].rm":
            context => "/files$path/table[ . = '$table_name']",
            changes => "
                rm append[ comment = '$rule' and preceding-sibling::$q]
                rm append[ comment = '$rule' and following-sibling::$q]
            ",
            require => Augeas["iptables.rule.[$name].add"],
            lens => 'Iptables.lns',
            incl => $path
        }
    }

    # Set contents of the rule
    augeas { "iptables.rule.[$name].edit":
        context => "/files$path/table[ . = '$table_name']/$q",
        changes => $changes,
        require => Augeas["iptables.rule.[$name].add"],
        lens => 'Iptables.lns',
        incl => $path
    }
}

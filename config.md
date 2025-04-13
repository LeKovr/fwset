
### Main Options

| Name | ENV | Type | Default | Description |
|------|-----|------|---------|-------------|
| COMMAND              | -                    | create,list,add,del |  | Команда |
| IP                   | -                    | []string |  | IP адрес (для команд add, del) |
| accept               | ACCEPT               | bool | `false` | Use Accept instead of Drop |
| fw                   | FW                   | nft,ipset | `nft` | Firewall type |
| table                | TABLE                | string | `myfirewall` | Table name |
| chain                | CHAIN                | string | `input` | Chain name |
| set_drop             | SET_DROP             | string | `blocked_nets` | Drop set name |
| set_accept           | SET_ACCEPT           | string | `allowed_nets` | Accept set name |
| version              | -                    | bool | `false` | Show version and exit |
| config_gen           | CONFIG_GEN           | ,json,md,mk |  | Generate and print config definition in given format and exit (default: '', means skip) |
| config_dump          | CONFIG_DUMP          | string |  | Dump config dest filename |

### Logging Options {#log}

| Name | ENV | Type | Default | Description |
|------|-----|------|---------|-------------|
| log.debug            | LOG_DEBUG            | bool | `false` | Show debug info |
| log.format           | LOG_FORMAT           | ,text,json |  | Output format (default: '', means use text if DEBUG) |
| log.time_format      | LOG_TIME_FORMAT      | string | `2006-01-02 15:04:05.000` | Time format for text output |
| log.dest             | LOG_DEST             | string |  | Log destination (default: '', means STDERR) |

# To build this project:

1.  Install cmake (version 3 or higher), libssl (openssl), and sqlite3
2.  If using homelink_cli, create the config file.  It can be placed any path by setting the environment variable ```$HOMELINK_CLI_CONFIG_PATH```, but by default it will be placed in ~/.homelink_config as cli_config.conf.  In the config, the host_id, server_address, server_control_port, and server_data_port should be set.  The control port is for UDP, the data port is for TCP.  Additionally, this can be done from the command line with ```homelink_cli --configure <options>```, the options are --server-address, --server-control-port, --server-data-port, and --host-id.
An example config file is shown:
```
host_id HOST
server_address 192.168.1.1
server_control_port 10000
server_data_port 10001
```
3.  Run the ```setup``` script in ```./scripts``` to build the server, daemon, and cli.  They also have their own respective build scripts.

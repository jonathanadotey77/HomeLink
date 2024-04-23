# To build this project:

1.  Install cmake (version 3 or higher), libssl (openssl), and sqlite3
2.  Create the config file.  It can be placed in the path ${HomeLink_Directory}/config/config.conf.  In the config, the host_id, server_address, server_control_port, and server_data_port should be set.  The control port is for UDP, the data port is for TCP.
An example is shown:
```config.conf
host_id HOST
server_address 192.168.1.1
server_control_port 10000
server_data_port 10001
```
3.  Initialize the environment variables.  This is best done in the .bashrc file. For the server, HOMELINK_ROOT must be set to the project root.  HOMELINK_CONFIG_PATH should be set to the path of the config file.  HOMELINK_DAEMON_FILES should be set to the location where files sent to the host should be stored.

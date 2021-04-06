# iptBanned
Enabling users without root access on servers to see which hosts are currently banned in IPTables.  We had a situation where the team supporting clients making inbound SFTP connections were frequently sending us tickets asking us to check if X client is on the ban list.  We use fail2ban to automatically ban IPs that are frequently failing to login.  To speed up this process I decided to give this team a simple web site that would list all of the IPs currently banned so that they could quickly see for themselves.

## Usage
iptBanned needs to be run as root because it needs access to iptables

By default iptBanned runs on port 8080 but you can change this using the -p flag:

```./iptBanned -p 80```

By default iptBanned gets the list of blocked IPs from the f2b-SSH chain which is generally what fail2ban uses however this can be changed with the -c flag:

```./iptBanned -c iptables-chain```

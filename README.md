# iptBanned
Enabling other users to see which hosts are currently banned in IPTables.  We had a situation where the team supporting clients making SFTP connections to us were frequently sending us tickets asking us to check if X client is on the ban list.  We use fail2ban to automatically ban IPs that are frequently failing to login.  To speed up this process I decided to give this team a simple web site that would list all of the IPs currently banned so that they could quickly see for themselves.

## Usage
iptBanned runs on port 8080.  Because it requires access to iptables it will need to be run as root user (or other user with access to iptables but usually root)

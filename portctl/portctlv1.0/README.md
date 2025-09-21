# portctl v1.0
Firewall + SELinux port control for Oracle Linux 9 / RHEL 9  
Author: Megah Djohari
  
    
## Features:
   - `open`/`close` ports (firewalld)
   - optional SELinux port mapping (`--type ssh_port_t | http_port_t |...`)
   - limit by source CIDR (--source 203.0.113.0/24) using rich rules
   - bulk ports support (space-separated list)
   - `dry-run mode` (prints actions only)
   - logging (`/var/log/portctl.log`)
   

## Usage
```bash

# Open custom SSH and auto-log if a container also publishes it
sudo ./portctl.sh open 4422/tcp --type ssh_port_t

# Open web ports (global) and see notices if Nginx/Traefik is publishing them
sudo ./portctl.sh open 8080/tcp 8443/tcp --type http_port_t

# Open only for your office subnet; still prints container notice if applicable
sudo ./portctl.sh open 9090/tcp --source 203.0.113.0/24

# Close the subnet-restricted rule
sudo ./portctl.sh close 9090/tcp --source 203.0.113.0/24

# Quick view
sudo ./portctl.sh list

```
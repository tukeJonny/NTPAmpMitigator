# NTP amp attack mitigator
CentOS7

# Build
## Mininet VM (Official mininet vm)

## Docker VM (docker-compose)
### Docker install
```bash
yum install docker
systemctl enable docker
systemctl start docker
curl -L "https://github.com/docker/compose/releases/download/1.9.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
```

Please change victim/roles/zabbix-agent/files/zabbix_agentd.conf !
IP Address is fix...

## Victim VM (Ansible)



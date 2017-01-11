#!/bin/sh

systemctl enable ntpd
systemctl start ntpd
firewall-cmd --add-service=ntp --permanent
firewall-cmd --reload


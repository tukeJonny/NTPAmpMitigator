FROM centos7:centos7
MAINTAINER tukejonny

RUN yum update -y && yum clean all
RUN yum swap -y fakesystemd systemd && yum clean all

ADD files/ntp-4.2.6p5-25.el7.centos.x86_64.rpm /tmp/ntp-4.2.6p5-25.el7.centos.x86_64.rpm
RUN rpm -ivh /tmp/ntp-4.2.6p5-25.el7.centos.x86_64.rpm

ADD files/ntp.conf /etc/ntp.conf



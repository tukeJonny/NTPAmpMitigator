FROM centos:7
MAINTAINER tukejonny

RUN yum update -y && yum clean all && \
    yum install -y \
        libedit \
        autogen-libopts \
        ntpdate
# RUN yum swap -y fakesystemd systemd && yum clean all

COPY files/ntp-4.2.6p5-25.el7.centos.x86_64.rpm /tmp/ntp-4.2.6p5-25.el7.centos.x86_64.rpm
RUN rpm -ivh --nosignature /tmp/ntp-4.2.6p5-25.el7.centos.x86_64.rpm

COPY files/ntp.conf /etc/ntp.conf
# COPY files/init.sh /tmp/init.sh

ENTRYPOINT ["/usr/sbin/ntpd"]
CMD ["-n","-b","-g","-l","stdout"]

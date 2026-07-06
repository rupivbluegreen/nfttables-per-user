FROM rockylinux:9
RUN dnf -y install \
        openssh-server openssh-clients \
        sssd sssd-ad sssd-tools adcli krb5-workstation authselect \
        nftables iproute iputils bind-utils procps-ng \
    && dnf clean all
# pam_sss in the stacks; homedirs via pam_mkhomedir (no oddjobd/dbus here)
RUN authselect select sssd --force \
    && echo 'session    optional     pam_mkhomedir.so umask=0077' >> /etc/pam.d/sshd
COPY krb5.conf /etc/krb5.conf
COPY sssd.conf /etc/sssd/sssd.conf
RUN chmod 600 /etc/sssd/sssd.conf && chown root:root /etc/sssd/sssd.conf
COPY etc-tunnelfw/ /etc/tunnelfw/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y openssh-server && \
    mkdir /var/run/sshd && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash securechat && \
    echo 'securechat:securepass12345' | chpasswd

COPY chat-client /home/securechat/chat-client

RUN chown securechat:securechat /home/securechat/chat-client && \
    chmod +x /home/securechat/chat-client

RUN echo 'cd ~ && ./chat-client' >> /home/securechat/.bashrc

RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    echo 'PermitUserEnvironment yes' >> /etc/ssh/sshd_config && \
    echo 'AllowUsers securechat' >> /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]

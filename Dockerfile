FROM ubuntu:22.04

WORKDIR /app

RUN apt update -y && apt install -y python3 python3-pip htop curl wget gnupg2 net-tools iproute2 vim nano 
ENV TZ=Asia/Tehran
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata && \
    ln -fs /usr/share/zoneinfo/$TZ /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

# Copy installer and scripts
COPY ./zeek/install.sh /app/install.sh
RUN chmod +x /app/install.sh && /app/install.sh

COPY ./zeek/pip-requirements.txt /app/pip-requirements.txt
RUN pip install -r /app/pip-requirements.txt
COPY ./zeek/ongoing_conns.zeek /opt/zeek/share/zeek/site/ongoing_conns.zeek
COPY ./zeek/configure.py /app/configure.py
COPY ./zeek/.env/ /app/.env
RUN python3 /app/configure.py
COPY ./zeek/run.sh /app/run.sh
RUN chmod +x /app/run.sh
# Do NOT deploy in build, deploy on container start
CMD ["/app/run.sh"]


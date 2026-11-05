FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    iproute2 \
    iputils-ping \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

CMD ["bash"]
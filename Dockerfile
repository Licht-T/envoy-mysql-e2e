FROM ubuntu:22.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY envoy /usr/local/bin/envoy
RUN chmod +x /usr/local/bin/envoy
ENTRYPOINT ["envoy"]

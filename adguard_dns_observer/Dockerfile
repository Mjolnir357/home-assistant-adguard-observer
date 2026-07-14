FROM python:3.13-alpine3.22

ARG BUILD_VERSION=dev
ARG BUILD_ARCH=aarch64

LABEL io.hass.version="${BUILD_VERSION}" \
      io.hass.type="app" \
      io.hass.arch="${BUILD_ARCH}"

WORKDIR /opt/adguard-dns-observer
COPY observer.py ./

ENTRYPOINT ["python3", "/opt/adguard-dns-observer/observer.py"]
CMD ["--config", "/data/options.json", "--state", "/data/state.json", "--events", "/data/events.jsonl"]


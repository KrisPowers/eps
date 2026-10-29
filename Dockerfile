# portscan's container: the dashboard (`portscan --serve`) and the page it
# serves. With arguments it runs one scan instead, like the CLI:
# `docker run --rm ghcr.io/krispowers/portscan 192.168.1.10`.

FROM --platform=$BUILDPLATFORM node:24.22.1-alpine AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY ui/ ./
RUN npm run build

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release -p cli

FROM debian:bookworm-slim
COPY --from=build /src/target/release/portscan /usr/local/bin/
COPY --from=ui /src/ui/dist/ /usr/share/portscan/web/
# A scan of `localhost` from the dashboard goes to the computer running the
# container, not the container itself.
ENV PORTSCAN_LOCALHOST=host.docker.internal
VOLUME /data
EXPOSE 8090
ENTRYPOINT ["portscan"]
CMD ["--serve", "0.0.0.0:8090", "--web", "/usr/share/portscan/web", "--data", "/data"]

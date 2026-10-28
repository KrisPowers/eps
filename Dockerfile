# `@` as an HTTP service (`--serve`), the container a dashboard such as
# truebrew starts scans through. See "Service mode" in the README.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release -p cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/at /usr/local/bin/at
VOLUME /data
EXPOSE 8080
# The key the dashboard hands out is mounted at /run/truebrew/key.
ENTRYPOINT ["at", "--serve", "0.0.0.0:8080", "--key-file", "/run/truebrew/key", "--data", "/data"]

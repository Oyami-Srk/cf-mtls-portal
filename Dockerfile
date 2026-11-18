FROM rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY web ./web
RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN mkdir -p /data /config /secrets && chown 10001:10001 /data
COPY --from=build /app/target/release/cf-mtls-portal /usr/local/bin/cf-mtls-portal
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=4s --start-period=10s --retries=3 CMD ["cf-mtls-portal", "healthcheck"]
ENTRYPOINT ["cf-mtls-portal"]
CMD ["serve", "/config/config.toml"]

# Chai PDP sidecar: build then ship a slim image.
FROM rust:1-slim AS build
WORKDIR /app
COPY . .
RUN cargo build -p chai_dsl --release --features server --example sidecar

FROM debian:stable-slim
COPY --from=build /app/target/release/examples/sidecar /usr/local/bin/chai-sidecar
# Mount your policy at /policy.chai (or set CHAI_POLICY_FILE); else a demo policy.
ENV CHAI_ADDR=0.0.0.0:8731
EXPOSE 8731
ENTRYPOINT ["chai-sidecar"]

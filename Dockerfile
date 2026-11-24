# syntax=docker/dockerfile:1

FROM rust:1-bookworm@1b9dc70890ec494e466c87f5ad41ad544bfb30ea6acc99a3e068c47a4ae3f23e AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && cargo build --release --locked \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked --bin selvedge-push \
    && strip target/release/selvedge-push

FROM gcr.io/distroless/cc-debian12:nonroot@9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f

COPY --from=builder --chown=0:0 --chmod=0555 \
    /app/target/release/selvedge-push /usr/local/bin/selvedge-push

USER nonroot:nonroot

ENV BIND_ADDR=0.0.0.0:8085

EXPOSE 8085

ENTRYPOINT ["/usr/local/bin/selvedge-push"]

FROM debian:latest

COPY ./target/release/forcefield /app/forcefield
COPY ./static /app/static

EXPOSE 8000
WORKDIR /app
CMD ["/app/forcefield"]

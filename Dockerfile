FROM debian:latest

COPY ./target/release/forcefield /app/forcefield
COPY ./static /app/static
COPY ./templates /app/templates

EXPOSE 8000
WORKDIR /app
CMD ["/app/forcefield"]

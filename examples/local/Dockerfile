# Builds blackbox_exporter from the checkout so local changes are what gets probed.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /blackbox_exporter .

FROM busybox:1.37
LABEL org.opencontainers.image.title="Blackbox Exporter (local example)"
COPY --from=build /blackbox_exporter /bin/blackbox_exporter
COPY blackbox.yml /etc/blackbox_exporter/config.yml

EXPOSE      9115
ENTRYPOINT  [ "/bin/blackbox_exporter" ]
CMD         [ "--config.file=/etc/blackbox_exporter/config.yml" ]

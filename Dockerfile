FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /fake-signicat .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /fake-signicat /fake-signicat
EXPOSE 8099
ENTRYPOINT ["/fake-signicat"]

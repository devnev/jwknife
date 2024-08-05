FROM golang:1.22-alpine AS build
COPY go.mod go.sum /src/
RUN cd /src && go mod download
COPY . /src
RUN cd /src && go build -o /jwknife .

FROM alpine
COPY --from=build /jwknife /usr/bin/
ENTRYPOINT ["/usr/bin/jwknife"]

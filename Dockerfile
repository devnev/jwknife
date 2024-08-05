# The following ARGs _should_ allow SBOM scanning to detect the licenses of the modules in the module cache in the build stage, and the license in the context, i.e. this module's license. See https://docs.docker.com/build/attestations/sbom/#arguments.
# For unknown reasons, the licenses are still listed as NOASSERTION. The ARGs are left here in case it magically starts working. Possibly related: https://github.com/anchore/syft/issues/1056.

# Have the SBOM include the license of dependencies
ARG BUILDKIT_SBOM_SCAN_STAGE=true
# Have the SBOM include the license in the source code
ARG BUILDKIT_SBOM_SCAN_CONTEXT=true

FROM golang:1.22-alpine AS build
COPY go.mod go.sum /src/
RUN cd /src && go mod download
COPY . /src
RUN cd /src && go build -o /jwknife .

FROM alpine
COPY --from=build /jwknife /usr/bin/
ENTRYPOINT ["/usr/bin/jwknife"]

# Azul Plugin Goinfo

An Azul plugin that uses the GoRE library to extract metadata from compiled Golang binaries.

## Local Build

`go build -v -tags netgo -ldflags '-w -extldflags "-static"' -o bin/azul-goinfo *.go`

## Docker Builds

An example dockerfile is provided for building images.
To use the container for a build run the following (or similar if your ssh private and public key for accessing Azure is in a non-standard file):

Example Build (requires you install `buildah` with `sudo apt install buildah`):

```bash
buildah build --volume ~/.ssh/known_hosts:/root/.ssh/known_hosts --ssh id=~/.ssh/id_rsa  .
```

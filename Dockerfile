
FROM debian:jessie
MAINTAINER Daniel Plominski <daniel@plominski.eu>

# Packaged dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    zsh \
    --no-install-recommends



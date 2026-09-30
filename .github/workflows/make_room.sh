#!/usr/bin/env bash

set -o errexit -o nounset -o pipefail

# Free disk space on a GitHub-hosted Linux runner by deleting preinstalled
# toolchains that nothing here uses.

sudo rm -rf /usr/share/dotnet /opt/ghc /usr/local/.ghcup \
  /opt/hostedtoolcache/CodeQL /usr/local/share/powershell \
  /usr/share/swift /usr/local/share/chromium /opt/google
sudo docker image prune --all --force
df -h

#!/usr/bin/env bash
set -euo pipefail

NS=xdp-test

up() {
	ip netns add "$NS"
	ip link add veth0 type veth peer name veth1
	ip link set veth1 netns "$NS"
	ip addr add 10.200.0.1/24 dev veth0
	ip link set veth0 up
	ip -n "$NS" addr add 10.200.0.2/24 dev veth1
	ip -n "$NS" link set veth1 up
}

down() {
	ip netns del "$NS"
}

check() {
    ip -br addr show veth0
    ip -n $NS -br addr show veth1
    ip netns exec $NS ping -c 3 10.200.0.1
}

case "${1:-}" in
up) up ;;
down) down ;;
check) check ;;
*)
	echo "Usage: sudo $0 {up|down|check}" >&2
	exit 1
	;;
esac

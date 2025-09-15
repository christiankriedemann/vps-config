#!/bin/bash

# ============================================================================
#                    DOCKER NAT FIX - Immediate Solution
# ============================================================================

echo "Fixing Docker NAT/MASQUERADE rules for outgoing connections..."

# Add MASQUERADE rules for Docker networks
# This allows containers to reach the internet

# For standard Docker network range
iptables -t nat -C POSTROUTING -s 172.16.0.0/12 ! -o docker0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 172.16.0.0/12 ! -o docker0 -j MASQUERADE

# For default bridge network
iptables -t nat -C POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE

# For Coolify/custom networks (common range)
iptables -t nat -C POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE

# Alternative: Masquerade everything not going to docker0 (broader rule)
# Uncomment if needed:
# iptables -t nat -C POSTROUTING ! -o docker0 -j MASQUERADE 2>/dev/null || \
#     iptables -t nat -A POSTROUTING ! -o docker0 -j MASQUERADE

# Save the rules
if command -v netfilter-persistent &>/dev/null; then
    netfilter-persistent save &>/dev/null
    echo "Rules saved permanently"
fi

echo "Docker NAT rules applied!"
echo ""
echo "Testing with: docker run --rm alpine ping -c 3 8.8.8.8"
docker run --rm alpine ping -c 3 8.8.8.8 2>/dev/null && echo "✓ Success!" || echo "✗ Still not working"

# NetworkPolicy Configuration for Test Pods

| Target | From self (Egress) | To pod (Ingress) |
|-|-|-|
| l3-ingress-explicit-allow-all (1) | allow | allow |
| l3-ingress-explicit-allow-all (2) | allow | allow |
| l3-ingress-implicit-deny-all | allow | - |
| l3-ingress-explicit-deny-all | allow | deny |
| l3-egress-implicit-deny-all | - | - |
| l3-egress-explicit-deny-all | deny | - |
| l4-ingress-explicit-allow-any | allow (L4) | allow (L4) |
| l4-ingress-explicit-allow-tcp | allow (L4) | allow (L4) |
| l4-ingress-explicit-deny-any | allow (L4) | deny (L4) |
| l4-ingress-explicit-deny-udp | allow (L4) | deny (L4) |
| l4-egress-explicit-deny-any | deny (L4) | - |
| l4-egress-explicit-deny-tcp | deny (L4) | - |
| l4-ingress-all-allow-tcp | - | allow (L4-only) |
| 8.8.8.8 (Google Public DNS) | allow (L4) | - |
| 8.8.4.4 (Google Public DNS)  | deny (L4) | - |

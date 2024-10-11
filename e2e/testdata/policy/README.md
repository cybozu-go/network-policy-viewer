# NetworkPolicy Configuration for Test Pods

| Target | From self (Egress) | To pod (Ingress) |
|-|-|-|
| l3-ingress-explicit-allow | allow | allow |
| l3-ingress-implicit-deny | allow | - |
| l3-ingress-explicit-deny | allow | deny |
| l3-egress-implicit-deny | - | - |
| l3-egress-explicit-deny | deny | - |
| l4-ingress-explicit-allow-any | allow (L4) | allow (L4) |
| l4-ingress-explicit-allow-tcp | allow (L4) | allow (L4) |
| l4-ingress-explicit-deny-any | allow (L4) | deny (L4) |
| l4-ingress-explicit-deny-udp | allow (L4) | deny (L4) |
| l4-egress-explicit-deny-any | deny (L4) | - |
| l4-egress-explicit-deny-tcp | deny (L4) | - |

# RouteTrace incident ad53230406ba

203.0.113.0/24 in VRF blue | R1 → R2 → R3
Capture: 2026-10-20T09:06:00Z | State: approved

## Finding
The prefix is selected locally, but its effective export policy denies advertisement to the egress peer.

## Observed evidence
- peer_view: withheld — transient-export/R2/blue/peer_view
- selected: present — transient-export/R2/blue/selected
- export_policy: deny — transient-export/R2/blue/export_policy

## Reviewer note
Sample reviewer checked the three source locators.

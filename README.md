# Enterprise Active Directory, Perimeter Security & Multi-Site Infrastructure Lab

[![Windows Server 2025](https://img.shields.io/badge/Windows%20Server-2025%20Std-0078D4?style=flat&logo=windows)](https://www.microsoft.com/evalcenter/evaluate-windows-server-2025)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-AD%20DS%20%7C%20DNS%20%7C%20GPO-0078D4?style=flat&logo=windows)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-domain-services)
[![pfSense](https://img.shields.io/badge/Firewall-pfSense%20CE%202.7.2-black?style=flat&logo=pfsense)](https://www.pfsense.org/)
[![NPS RADIUS](https://img.shields.io/badge/AAA-Windows%20NPS%20%28RADIUS%29-blue?style=flat)](https://learn.microsoft.com/en-us/windows-server/networking/technologies/nps/nps-top)
[![IPsec IKEv2](https://img.shields.io/badge/VPN-IPsec%20IKEv2%20%28EAP--RADIUS%29-red?style=flat)](https://docs.netgate.com/pfsense/en/latest/vpn/ipsec/index.html)
[![Tailscale ZTNA](https://img.shields.io/badge/Zero--Trust-Tailscale%20WireGuard-0052CC?style=flat&logo=tailscale)](https://tailscale.com/)
[![PKI](https://img.shields.io/badge/Security-X.509%20Internal%20PKI-green?style=flat)](https://docs.netgate.com/pfsense/en/latest/certificates/index.html)
[![Lab Status](https://img.shields.io/badge/Lab%20Status-Production--Validated-brightgreen?style=flat)](#)

A comprehensive, production-validated enterprise systems and network engineering lab. This project documents the complete lifecycle—design, deployment, failure diagnosis, security hardening, and remote access integration—of a multi-site enterprise infrastructure spanning **Windows Server 2025 Active Directory Domain Services (AD DS)**, **pfSense stateful firewalls**, **centralized RADIUS/NPS authentication**, **enterprise IKEv2 IPsec VPN**, and **Zero-Trust Tailscale mesh overlay routing**.

---

## Architecture Overview

```
                                      +------------------------------------+
                                      |      Remote Engineer Workstation   |
                                      |   Tailscale IP: 100.106.74.113     |
                                      +------------------------------------+
                                               |                   |
                                (WireGuard Mesh Overlay)    (IKEv2 IPsec EAP-RADIUS)
                                               |                   |
                                               v                   v
                                      +------------------------------------+
                                      |     Simulated WAN / Transit Net    |
                                      |           192.168.23.0/24          |
                                      |       Upstream GW: 192.168.23.2    |
                                      +------------------------------------+
                                             /                      \\
                 +--------------------------+                        +--------------------------+
                 |    WAN: 192.168.23.138   |                        |    WAN: 192.168.23.139   |
                 |          FW-HQ           |                        |        FW-Branch         |
                 |   (pfSense CE 2.7.2)     |                        |   (pfSense CE 2.7.2)     |
                 |    LAN: 192.168.10.1     |                        |    LAN: 192.168.20.1     |
                 +--------------------------+                        +--------------------------+
                              |                                                   |
           ========================================            ========================================
           HQ Corporate Network (192.168.10.0/24)              Branch Office Network (192.168.20.0/24)
           ========================================            ========================================
             |                                  |                                  |
             v                                  v                                  v
+--------------------------+       +--------------------------+       +--------------------------+
|      DC01.lab.local      |       |      PC01.lab.local      |       |     Branch PC (Win 11)   |
|   Windows Server 2025    |       |   Windows 11 Enterprise  |       |   IP: 192.168.20.x/24    |
|   IP: 192.168.10.10/24   |       |   IP: 192.168.10.20/24   |       |   GW: 192.168.20.1       |
|                          |       |                          |       +--------------------------+
| Roles & Services:        |       | Features:                |
| - Active Directory DS    |       | - Domain Member          |
| - DNS Zone (lab.local)   |       | - GPO Baseline Enforced  |
| - NPS (RADIUS AAA)       |       | - Mapped Drives (B:, K:) |
| - Department File Shares |       | - Restricted Edge Browser|
| - hMailServer & eM Client|       +--------------------------+
+--------------------------+
```

---

## Master Addressing & Component Matrix

| Host / Node | Role / OS | Subnet / Interface | IP Address | Gateway & DNS Targets |
| :--- | :--- | :--- | :--- | :--- |
| **DC01** | Windows Server 2025 Std (AD DS, DNS, NPS) | LAN (HQ Site) | `192.168.10.10/24` | GW: `192.168.10.1` \| DNS: `127.0.0.1` |
| **PC01** | Windows 11 Enterprise (Domain Joined) | LAN (HQ Site) | `192.168.10.20/24` | GW: `192.168.10.1` \| DNS: `192.168.10.10` |
| **FW-HQ** | pfSense CE 2.7.2 / FreeBSD 16.0 (Gateway) | em1 (LAN)<br>em0 (WAN) | `192.168.10.1/24`<br>`192.168.23.138/24` | WAN GW: `192.168.23.2`<br>DNS Forwarding Enabled |
| **FW-Branch** | pfSense CE 2.7.2 / FreeBSD 16.0 (Branch GW) | em1 (LAN)<br>em0 (WAN) | `192.168.20.1/24`<br>`192.168.23.139/24` | WAN GW: `192.168.23.2`<br>DNS Forwarding Enabled |
| **Branch PC** | Windows 11 Client (Branch Workstation) | LAN (Branch Site) | `192.168.20.x/24` | GW: `192.168.20.1` \| DNS: pfSense / DC01 |
| **Simulated WAN** | Hypervisor Virtual Switch / Routed Segment | Transit Subnet | `192.168.23.0/24` | Upstream NAT GW: `192.168.23.2` |
| **IPsec Mobile Pool** | Virtual Client Pool (IKEv2 EAP-RADIUS) | Dial-In Virtual IP | `10.10.100.0/24` | Encapsulated to `192.168.10.0/24` |
| **Tailscale Overlay** | WireGuard Subnet Router (pfSense Node) | Overlay CGNAT IP | `100.115.4.8` (FW)<br>`100.106.74.113` (Ext) | Advertised Route: `192.168.10.0/24` |

---

## Key Engineering Highlights

### 1. Active Directory Identity & Access Governance
- **Role-Based Access Control (AGDLP Framework):** Rigorous separation of identity and permission scopes: **A**ccounts (`Ayo`, `Huzzy`, `Suarez`) -> **G**lobal Groups (`GG_Accounting`, `GG_Banking`) -> **D**omain **L**ocal Groups (`DL_AccountingModifier`, `DL_Banking`) -> **P**ermissions on file system ACLs.
- **File Server Security (NTFS vs Share Permissions):** Broadened share permissions (`Authenticated Users = Change`) while enforcing strict least privilege in NTFS. Default inheritance was severed to close the built-in domain-wide `Users` read leak. Subfolder isolation demonstrated with `Banking\HR_PRIVATE` restricted exclusively to `HR_Private` and verified via Effective Access evaluation.
- **Group Policy Preferences (GPP) with Item-Level Targeting (ILT):** Dynamically maps department drives (`B:` for Accounting, `K:` for Banking) based on security group membership, replacing fragile batch logon scripts.
- **Workstations Baseline Security GPO:** Applied to `OU=Workstations`:
  - 15-minute machine inactivity auto-lock (`Interactive logon: Machine inactivity limit = 900`).
  - Legal compliance warning banner on logon.
  - Windows Defender Firewall mandatory enforcement (Inbound Block across Domain, Private, Public).
  - Removable Storage Access lockdown (Deny all USB mass storage).
- **Enterprise Edge URL Governance:** Deployed Microsoft Edge ADMX templates into the SYSVOL Central Store. Enforced corporate browsing allow-list (`URLBlocklist = *`, `URLAllowlist = microsoft.com, bing.com, lab.local, edge://*`).

### 2. Multi-Site Perimeter Security & Routing (pfSense)
- **Network Segmentation:** Transitioned from a flat test sandbox to an enterprise multi-site architecture with dedicated security zones (HQ LAN, Branch LAN, Transit WAN).
- **Default Gateway Re-Architecture:** Migrated all Windows servers and workstations to adopt pfSense as their default gateway (`192.168.10.1`), enabling stateful packet inspection and outbound NAT.
- **Stateful Packet Inspection & Transit Rules:** Permitted ICMP diagnostic polling between perimeter firewalls across the simulated WAN.
- **Deep Packet Inspection (pcap):** Executed live packet captures on WAN interfaces (`em0`) to inspect outbound NAT state translations, UDP/TCP traffic streams, and bidirectional ICMP exchanges.

### 3. Centralized AAA Integration: Windows Server NPS (RADIUS)
- **Zero Local Users on Perimeter Gateways:** Offloaded all VPN and administrative authentication from pfSense to Active Directory Domain Services.
- **Network Policy Server (NPS) Deployment:** Installed and authorized NPS in the Active Directory domain root.
- **RADIUS Client Configuration:** Registered `pfSense-HQ` (`192.168.10.1`) with a dedicated cryptographic shared secret (`Pass123`).
- **Network Policy Hardening (`VPN-Allow`):** Restricted authentication strictly to **MS-CHAP-v2** for `LAB\Domain Users`, eliminating vulnerable legacy authentication protocols (PAP/SPAP/CHAP).
- **Diagnostic AAA Verification:** Validated end-to-end credential verification directly from pfSense `Diagnostics > Authentication`.

### 4. Enterprise IKEv2 IPsec Mobile Client VPN
- **Internal Public Key Infrastructure (PKI):** Built an internal Certificate Authority (`Lab-CA`, RSA 2048-bit, SHA256) valid through 2036.
- **VPN Server Certificate with SAN:** Generated `VPN-Server-Cert` containing an explicit **Subject Alternative Name (SAN: `192.168.23.138`)** to satisfy strict native Windows IKEv2 client validation.
- **IKEv2 EAP-RADIUS Suite:**
  - **Phase 1 (IKE SA):** IKEv2, AES-256, SHA256, DH Group 14 (2048-bit), MOBIKE enabled, Dead Peer Detection (DPD 10s).
  - **Phase 2 (Child SA):** ESP, AES-256 / AES-GCM-128, SHA256, 3600s lifetime with 3240s rekey.
- **Stateful Tunnel Firewall Rules:** Created WAN pass rules for UDP 500 (ISAKMP) / UDP 4500 (NAT-T) and authorized decapsulated payload transit from virtual pool `10.10.100.0/24` to `192.168.10.0/24`.

### 5. Next-Gen Zero-Trust Mesh Remote Access (Tailscale)
- **pfSense Subnet Router:** Deployed `pfSense-pkg-Tailscale` directly onto the gateway, advertising `192.168.10.0/24` into the private Tailnet.
- **Zero-Touch Client Access:** External administrators connect to internal domain controllers over WireGuard mesh without installing VPN software on DC01 or port-forwarding on the firewall.
- **Cross-Subnet PowerShell Verification:** Proved direct TCP port 3389 reachability (`Test-NetConnection -Port 3389` -> `TcpTestSucceeded: True`) from an external Tailscale client (`100.106.74.113`) to DC01 (`192.168.10.10`).
- **Encrypted Remote Desktop Management:** Authenticated domain administration session established cleanly over the mesh tunnel.

### 6. Endpoint Trust Store Management
- Deployed and anchored `Lab-CA.crt` into the Windows **Trusted Root Certification Authorities** certificate store, eliminating cryptographic trust warnings and establishing mutual authentication anchors.

---

## Field Troubleshooting & Engineering Gotchas

| Issue / Failure State | Root Cause Analysis | Remediation Protocol |
| :--- | :--- | :--- |
| **Mail trapped in Outbox; intermittent domain login timeouts.** | **Dual-Homing DNS Hijacking:** When a VM has both an internal LAN adapter and a NAT adapter, Windows prioritizes the adapter with the Default Gateway (NAT). All DNS queries for `lab.local` are routed to the NAT router, which cannot resolve internal records. | Adjust interface metrics using PowerShell: `Set-NetIPInterface -InterfaceAlias "Ethernet0" -InterfaceMetric 10` (LAN preferred) and `Set-NetIPInterface -InterfaceAlias "Ethernet1" -InterfaceMetric 50` (NAT). Untick *"Register this connection's addresses in DNS"* on the NAT adapter. Run `ipconfig /flushdns`. |
| **pfSense inter-site ping returns 100% packet loss.** | **Stateful Default-Deny:** pfSense automatically drops all unsolicited inbound WAN traffic by default. | Create an explicit pass rule on **Firewall > Rules > WAN**: Protocol `IPv4 ICMP`, Subtype `Echo Request`, Destination `WAN address`. |
| **Windows IKEv2 VPN fails with Error 13801.** | **Missing SAN IP in Server Certificate:** Windows native VPN strictly requires the connection address (IP or FQDN) to match a Subject Alternative Name (SAN) entry in the server certificate. | Issue server certificate with SAN Type: `IP Address = 192.168.23.138`. Import `Lab-CA.crt` into the local machine's `Trusted Root Certification Authorities` store. |
| **GPO Wallpaper displays blank / black background.** | **Local vs UNC Path Trap:** Referencing `C:\Wallpaper\Team.jpg` in GPO works on the DC where the file exists, but fails on client machines where `C:\Wallpaper` does not exist. | Store the image in a shared network folder (`\\DC01\Wallpaper\Team.jpg`) accessible by `Authenticated Users (Read)` and specify the UNC path in the GPO. |
| **Tailscale CLI reports 'invalid key: API key does not exist'.** | Node initialized on CLI without prior authentication token. | Run `tailscale up --advertise-routes=192.168.10.0/24`, open the printed URL in a browser to authenticate via SSO, and approve the subnet route in the Tailscale Admin Console. |
| **Edge browser URL Allowlist blocks internal pages.** | `URLBlocklist = *` blocks internal browser schemes (`edge://*`). | Explicitly append `edge://*` and `chrome://*` to the `URLAllowlist` policy. |

---

## Verification & Testing Gallery

The project includes **83 verified screenshots** capturing every configuration step and diagnostic test:

```
images/
|-- image1.png  - image14.png : DC Static IP, AD DNS (A & MX), hMailServer, eM Client, Dual-Homed DNS Fix
|-- image15.png - image31.png : pfSense FW-HQ & FW-Branch Deployment, Routing, WAN ICMP Rules, Packet Captures
|-- image32.png - image42.png : Windows Server NPS Installation, AD Registration, RADIUS Client & Policy, Auth Test
|-- image43.png - image65.png : Internal PKI (Lab-CA), VPN Server Cert with SAN, IPsec Mobile Clients, Phase 1 & 2, Firewall Rules
|-- image66.png - image79.png : pfSense Tailscale Installation, Subnet Routing, Admin Route Approval, Port 3389 Verification, RDP
`-- image80.png - image83.png : Windows Client Root CA Certificate Import Wizard & Trust Store Verification
```

### Key Verification Commands
```powershell
# Verify DC static IP configuration
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.PrefixOrigin -eq "Manual"}

# Test socket reachability to mail and RDP ports
Test-NetConnection -ComputerName 192.168.10.10 -Port 25
Test-NetConnection -ComputerName 192.168.10.10 -Port 3389

# Test cross-subnet routing over Tailscale mesh overlay
Test-NetConnection -ComputerName 192.168.10.10 -Port 3389  # Run from external Tailscale client

# Validate Active Directory Group Policy application
gpresult /r /scope computer
gpresult /r /scope user
```

---

## Repository Documentation Assets

- **[Active Directory Project.docx](./Active%20Directory%20Project.docx):** The master, publication-grade technical report (7.9 MB, 410 paragraphs, 15 tables) with all 83 high-resolution screenshots embedded with figure numbers and detailed engineering narratives.
- **[Active_Directory_Enterprise_Lab_Documentation.md](./Active_Directory_Enterprise_Lab_Documentation.md):** Complete, self-contained Markdown documentation companion.
- **[images/](./images/):** Directory containing all 83 project screenshot artifacts.

---

## Technical Competencies Demonstrated

- **Directory Services & Identity:** Active Directory DS, Group Policy (GPO/GPP), Kerberos, DNS, Network Policy Server (NPS / RADIUS), AGDLP RBAC.
- **Network Engineering & Firewalls:** pfSense CE, Multi-Site Network Segmentation, Stateful Firewall Inspection, Outbound NAT, Inter-VLAN Routing, Deep Packet Inspection (pcap / tcpdump).
- **Security & Cryptography:** Public Key Infrastructure (X.509, Root CA, SAN Certificates, Trust Stores), IPsec IKEv2 (ESP, AES-256, Diffie-Hellman Group 14, MOBIKE), WireGuard Mesh (ZTNA), MS-CHAP-v2, NTFS Discretionary Access Control Lists (DACL).
- **System Administration & Automation:** Windows Server 2025, Windows 11 Enterprise, FreeBSD, PowerShell scripting, Network socket testing, Central Store ADMX templates.

---

## Author

**Odunuga Fatai Olayinka**  
*IT Systems & Network Engineering Lab Portfolio*  
*October – November 2026*

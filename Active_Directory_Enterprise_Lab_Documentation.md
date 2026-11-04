# Enterprise Active Directory, Perimeter Security & Remote Access Lab
### A Comprehensive Technical Architecture, Deployment & Hardening Field Guide

**Author:** Odunuga Fatai Olayinka  
**Date:** October – November 2026  
**Environment:** Windows Server 2025 Standard, Windows 11 Enterprise, pfSense Community Edition 2.7.2, Active Directory Domain Services (AD DS)  
**Project Status:** Production-Validated Lab  

---

## Table of Contents
1. [Executive Summary & Architectural Overview](#1-executive-summary--architectural-overview)
2. [Master Environment Specifications & Addressing Matrix](#2-master-environment-specifications--addressing-matrix)
3. [Chapter 1: Windows Server 2025, Active Directory & Mail Services](#3-chapter-1-windows-server-2025-active-directory--mail-services)
   - [Part 0 & 1: Static IP Addressing & Network Persistence](#part-0--1-static-ip-addressing--network-persistence)
   - [Part 2: Active Directory DNS Architecture for Mail Delivery](#part-2-active-directory-dns-architecture-for-mail-delivery)
   - [Parts 3–5: hMailServer Engine, Relay Permissions & Port Security](#parts-35-hmailserver-engine-relay-permissions--port-security)
   - [Part 6: Mail Client Provisioning (eM Client)](#part-6-mail-client-provisioning-em-client)
   - [Part 7: Verification & Health Checks](#part-7-verification--health-checks)
   - [Part 8: Troubleshooting & The Dual-Homing DNS Hijacking Trap](#part-8-troubleshooting--the-dual-homing-dns-hijacking-trap)
4. [Chapter 2: Active Directory Administration, Permissions & Group Policy](#4-chapter-2-active-directory-administration-permissions--group-policy)
   - [Section 1: The AGDLP Methodology & Group Scoping](#section-1-the-agdlp-methodology--group-scoping)
   - [Section 2: File Server Security: NTFS vs Share Permissions](#section-2-file-server-security-ntfs-vs-share-permissions)
   - [Section 3: Department File Server Build & Permission Hardening](#section-3-department-file-server-build--permission-hardening)
   - [Section 4: Automated Drive Mapping via Group Policy Preferences (GPP)](#section-4-automated-drive-mapping-via-group-policy-preferences-gpp)
   - [Section 5: Workstation Baseline Security Policy](#section-5-workstation-baseline-security-policy)
   - [Section 6: Centralized Wallpaper & The UNC Path Gotcha](#section-6-centralized-wallpaper--the-unc-path-gotcha)
   - [Section 7: Enterprise Web Browsing Restrictions via Edge Policy Templates](#section-7-enterprise-web-browsing-restrictions-via-edge-policy-templates)
5. [Chapter 3: Enterprise Perimeter Security & Multi-Site Networking with pfSense](#5-chapter-3-enterprise-perimeter-security--multi-site-networking-with-pfsense)
   - [Section 1: Architectural Evolution: From Flat Lab to Multi-Site Topology](#section-1-architectural-evolution-from-flat-lab-to-multi-site-topology)
   - [Section 2: Deploying FW-HQ & Gateway Re-Addressing](#section-2-deploying-fw-hq--gateway-re-addressing)
   - [Section 3: Deploying FW-Branch & Branch Client Verification](#section-3-deploying-fw-branch--branch-client-verification)
   - [Section 4: pfSense WebGUI Management & System Hardening](#section-4-pfsense-webgui-management--system-hardening)
   - [Section 5: Inter-Firewall Transit Rules & ICMP Telemetry](#section-5-inter-firewall-transit-rules--icmp-telemetry)
   - [Section 6: Branch Office Provisioning & Administrative Security](#section-6-branch-office-provisioning--administrative-security)
   - [Section 7: Deep Packet Inspection & Diagnostic Verification](#section-7-deep-packet-inspection--diagnostic-verification)
6. [Chapter 4: Enterprise Identity Integration: Windows Server NPS (RADIUS) & pfSense AAA](#6-chapter-4-enterprise-identity-integration-windows-server-nps-radius--pfsense-aaa)
   - [Section 1: The Centralized AAA Architecture](#section-1-the-centralized-aaa-architecture)
   - [Section 2: Installing & Authorizing Network Policy Server in Active Directory](#section-2-installing--authorizing-network-policy-server-in-active-directory)
   - [Section 3: Registering pfSense as a RADIUS Client in NPS](#section-3-registering-pfsense-as-a-radius-client-in-nps)
   - [Section 4: Authoring the Enterprise Network Access Policy](#section-4-authoring-the-enterprise-network-access-policy)
   - [Section 5: Validating RADIUS AAA Integration from pfSense](#section-5-validating-radius-aaa-integration-from-pfsense)
7. [Chapter 5: Public Key Infrastructure (PKI) & Enterprise IKEv2 Mobile Client VPN](#7-chapter-5-public-key-infrastructure-pki--enterprise-ikev2-mobile-client-vpn)
   - [Section 1: Establishing the Internal Certificate Authority (Lab-CA)](#section-1-establishing-the-internal-certificate-authority-lab-ca)
   - [Section 2: Generating the VPN Server Certificate (VPN-Server-Cert)](#section-2-generating-the-vpn-server-certificate-vpn-server-cert)
   - [Section 3: Configuring IPsec Mobile Client Core Settings](#section-3-configuring-ipsec-mobile-client-core-settings)
   - [Section 4: Authoring the IPsec Phase 1 Proposal (IKE SA)](#section-4-authoring-the-ipsec-phase-1-proposal-ike-sa)
   - [Section 5: Authoring the IPsec Phase 2 Proposal (Child IPsec SA)](#section-5-authoring-the-ipsec-phase-2-proposal-child-ipsec-sa)
   - [Section 6: State-Enforced Firewall Rules for IPsec](#section-6-state-enforced-firewall-rules-for-ipsec)
8. [Chapter 6: Next-Generation Zero-Trust Remote Access: Tailscale Mesh Subnet Router](#8-chapter-6-next-generation-zero-trust-remote-access-tailscale-mesh-subnet-router)
   - [Section 1: Deploying the Tailscale Package on pfSense](#section-1-deploying-the-tailscale-package-on-pfsense)
   - [Section 2: Configuring Tailscale & Subnet Route Advertisement](#section-2-configuring-tailscale--subnet-route-advertisement)
   - [Section 3: Authenticating the Node via pfSense CLI](#section-3-authenticating-the-node-via-pfsense-cli)
   - [Section 4: Tailscale Admin Console Route Approval](#section-4-tailscale-admin-console-route-approval)
   - [Section 5: pfSense Firewall Policy for Tailscale Traffic](#section-5-pfsense-firewall-policy-for-tailscale-traffic)
   - [Section 6: External Client Connection & RDP Management Verification](#section-6-external-client-connection--rdp-management-verification)
9. [Chapter 7: Endpoint Security, Client Trust & Certificate Store Management](#9-chapter-7-endpoint-security-client-trust--certificate-store-management)
   - [Section 1: Inspecting the Untrusted Certificate State](#section-1-inspecting-the-untrusted-certificate-state)
   - [Section 2: Deploying the Root CA via the Certificate Import Wizard](#section-2-deploying-the-root-ca-via-the-certificate-import-wizard)
   - [Section 3: Enterprise Automated Certificate Distribution](#section-3-enterprise-automated-certificate-distribution)
10. [Chapter 8: Comprehensive Troubleshooting Field Guide & Enterprise Takeaways](#10-chapter-8-comprehensive-troubleshooting-field-guide--enterprise-takeaways)
    - [Section 1: The Unified 4-Layer Diagnostic Methodology](#section-1-the-unified-4-layer-diagnostic-methodology)
    - [Section 2: Master Diagnostic & Failure Resolution Matrix](#section-2-master-diagnostic--failure-resolution-matrix)
    - [Section 3: Enterprise Hardening & Architectural Next Steps](#section-3-enterprise-hardening--architectural-next-steps)

---

## 1. Executive Summary & Architectural Overview

This engineering documentation details the design, deployment, verification, and hardening of an enterprise hybrid infrastructure lab. Commencing with a single Windows Server 2025 Domain Controller (`lab.local`) governing Active Directory Domain Services (AD DS), DNS, and messaging, the project systematically expands into an enterprise-class, multi-site network protected by redundant pfSense firewalls, centralized RADIUS/NPS authentication, enterprise IKEv2 IPsec VPN, and Zero-Trust Tailscale mesh overlay routing.

Every phase reflects hands-on testing across virtualized hypervisors, capturing real failure states, packet captures, and step-by-step diagnostic workflows.

---

## 2. Master Environment Specifications & Addressing Matrix

| Component / Node | Operating System / Role | Interface / Subnet | IP Address | Gateway / DNS Target |
| :--- | :--- | :--- | :--- | :--- |
| **DC01 (Server)** | Windows Server 2025 Std (AD DS, DNS, NPS) | LAN (HQ) | `192.168.10.10/24` | GW: `192.168.10.1` \| DNS: `127.0.0.1` |
| **PC01 (Client)** | Windows 11 Enterprise (Domain Joined) | LAN (HQ) | `192.168.10.20/24` | GW: `192.168.10.1` \| DNS: `192.168.10.10` |
| **FW-HQ (Firewall)** | pfSense CE 2.7.2 / FreeBSD 16.0 | em1 (LAN)<br>em0 (WAN) | `192.168.10.1/24`<br>`192.168.23.138/24` | WAN GW: `192.168.23.2`<br>DNS Forwarder enabled |
| **FW-Branch (Firewall)**| pfSense CE 2.7.2 / FreeBSD 16.0 | em1 (LAN)<br>em0 (WAN) | `192.168.20.1/24`<br>`192.168.23.139/24` | WAN GW: `192.168.23.2`<br>DNS Forwarder enabled |
| **Branch Client** | Windows 11 Client (Branch Site) | LAN (Branch) | `192.168.20.x/24` | GW: `192.168.20.1` \| DNS: pfSense / DC01 |
| **Simulated WAN Transit**| Hypervisor Virtual Switch / Bridge | Transit Subnet | `192.168.23.0/24` | Upstream NAT GW: `192.168.23.2` |
| **IPsec Mobile Pool** | Remote Dial-In (IKEv2 EAP-RADIUS) | Virtual Tunnel Pool | `10.10.100.0/24` | Encapsulated to HQ LAN (`192.168.10.0/24`) |
| **Tailscale Mesh Overlay**| WireGuard Subnet Router (pfSense) | Overlay CGNAT Subnet | `100.115.4.8` (FW)<br>`100.106.74.113` (PC) | Advertises: `192.168.10.0/24` |

---

## 3. Chapter 1: Windows Server 2025, Active Directory & Mail Services

### Part 0 & 1: Static IP Addressing & Network Persistence
A domain controller must maintain a fixed IP address. If a Domain Controller were to receive dynamic DHCP leases, DNS pointers would drift, immediately collapsing Kerberos authentication and GPO replication across the domain.

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "169.*" -and $_.IPAddress -ne "127.0.0.1"} | Select-Object IPAddress, PrefixOrigin
```

A `PrefixOrigin` of `Manual` confirms static binding.

![Figure 1: DC01 Network Adapter Configuration](./images/image1.png)  
*Figure 1: DC01 Network Adapter Configuration — Static assignment of IPv4 192.168.10.10/24 with loopback DNS (127.0.0.1).*

### Part 2: Active Directory DNS Architecture for Mail Delivery
Email delivery requires two separate DNS queries: an **MX (Mail Exchanger)** query to determine the designated mail server host for `@lab.local`, and an **A (Host)** query to resolve that hostname to an IP address.

1. **Host (A) Record:** Name: `mail`, IP: `192.168.10.10` -> `mail.lab.local`
2. **Mail Exchanger (MX) Record:** Host: `[Blank]` (root domain `@lab.local`), FQDN: `mail.lab.local`, Priority: `10`

![Figure 2: Active Directory DNS Zone Records](./images/image2.png)  
*Figure 2: Active Directory DNS Zone Records — The lab.local Forward Lookup Zone displaying Host (A) and MX records.*

Verify resolution:
```powershell
nslookup -type=mx lab.local
nslookup mail.lab.local
```

### Parts 3–5: hMailServer Engine, Relay Permissions & Port Security
hMailServer utilizes an embedded SQL Compact database. Under **Settings > Advanced > IP Ranges**, the local network range (`192.168.10.0/24`) must be explicitly authorized for SMTP, IMAP, and POP3 deliveries.

![Figure 3: hMailServer Subnet Access Rules](./images/image3.png)  
*Figure 3: hMailServer Subnet Access Rules — Configuring the 'Lab' IP range (192.168.10.0/24) for local delivery.*

Open firewall ports on DC01:
```powershell
New-NetFirewallRule -DisplayName "Mail SMTP" -Direction Inbound -Protocol TCP -LocalPort 25 -Action Allow
New-NetFirewallRule -DisplayName "Mail IMAP" -Direction Inbound -Protocol TCP -LocalPort 143 -Action Allow
New-NetFirewallRule -DisplayName "Mail POP3" -Direction Inbound -Protocol TCP -LocalPort 110 -Action Allow
```

![Figure 4: hMailServer Port Bindings & Listener Status](./images/image4.png)  
*Figure 4: hMailServer Port Bindings — Daemon listening on Ports 25 (SMTP), 110 (POP3), 143 (IMAP), and 587 (Submission).*

### Part 6: Mail Client Provisioning (eM Client)
eM Client is installed on the client machine. Because `lab.local` is private, manual setup is selected:
- **Incoming (IMAP):** `mail.lab.local`, Port `143`, Security: *Don't use secure connection*
- **Outgoing (SMTP):** `mail.lab.local`, Port `25`, Security: *Don't use secure connection*
- **Username:** `john@lab.local` (full address required)

![Figure 5: eM Client SMTP Configuration](./images/image5.png)  
*Figure 5: eM Client SMTP Configuration — Manual parameter entry for mail.lab.local on Port 25.*

### Part 7: Verification & Health Checks
A test message is dispatched from `Cane@lab.local` to `Ayo@lab.local`:

![Figure 6: Live Mail Composition & Dispatch](./images/image6.png)  
*Figure 6: Live Mail Composition & Dispatch — Sending email between domain users.*

Transport and socket verification via PowerShell:
```powershell
Test-NetConnection 192.168.10.10 -Port 25
Send-MailMessage -From "Cane@lab.local" -To "Ayo@lab.local" -Subject "PowerShell Test" -Body "Direct SMTP injection" -SmtpServer "192.168.10.10"
```

![Figure 7: TCP Socket Test](./images/image7.png)  
*Figure 7: TCP Socket Test — PowerShell confirms TcpTestSucceeded: True on Port 25.*

![Figure 8: Automated SMTP Dispatch](./images/image8.png)  
*Figure 8: Automated SMTP Dispatch — Send-MailMessage completes cleanly.*

![Figure 9: hMailServer Diagnostics Utility](./images/image9.png)  
*Figure 9: hMailServer Diagnostics Utility — Diagnostic test suite reporting all green checks for lab.local.*

### Part 8: Troubleshooting & The Dual-Homing DNS Hijacking Trap
When virtual machines are assigned two network adapters (Internal LAN Segment + NAT), Windows sends all DNS queries to the adapter with the Default Gateway (the NAT adapter). Because NAT DNS does not know `lab.local`, domain queries fail.

![Figure 10: Message Trapped in Outbox](./images/image10.png)  
*Figure 10: Message Trapped in Outbox — Mail stuck in Outbox due to unresolvable SMTP addresses.*

![Figure 11: Healthy Account State Post-Remediation](./images/image11.png)  
*Figure 11: Healthy Account State Post-Remediation — Both IMAP and SMTP reporting Ok after DNS resolution fix.*

![Figure 12: Dual-Homed Network Adapters](./images/image12.png)  
*Figure 12: Dual-Homed Network Adapters — Ethernet0 (Internal LAN) and Ethernet1 (NAT) competing for route precedence.*

![Figure 13: DNS Pollution & Split Resolution](./images/image13.png)  
*Figure 13: DNS Pollution & Split Resolution — nslookup returning both 192.168.10.10 and rogue NAT IP 192.168.23.133.*

**Remediation Protocol:**
```powershell
Set-NetIPInterface -InterfaceAlias "Ethernet0" -InterfaceMetric 10  # Internal LAN preferred
Set-NetIPInterface -InterfaceAlias "Ethernet1" -InterfaceMetric 50  # NAT less preferred
ipconfig /flushdns
```

![Figure 14: Disabling Dynamic DNS Registration on NAT Adapter](./images/image14.png)  
*Figure 14: Disabling Dynamic DNS Registration on NAT Adapter — Unchecking 'Register this connection's addresses in DNS'.*

---

## 4. Chapter 2: Active Directory Administration, Permissions & Group Policy

### Section 1: The AGDLP Methodology & Group Scoping
Permissions must never be granted directly to users. The AGDLP framework enforces:
- **A (Account):** User identities (`Ayo`, `Huzzy`, `Suarez`).
- **G (Global Group):** Role-based (`GG_Accounting`, `GG_Banking`).
- **DL (Domain Local Group):** Resource-based (`DL_AccountingModifier`, `DL_Banking`).
- **P (Permission):** Access control entry on target resource.

### Section 2: File Server Security: NTFS vs Share Permissions
- **Share Permissions:** Gate on the front door; network only; coarse control.
- **NTFS Permissions:** Vault lock on each room; network and local; granular control.
- **Rule of Evaluation:** The **most restrictive** permission applies.

### Section 3: Department File Server Build & Permission Hardening
1. Provisioned `C:\Shares\Accounting` and `C:\Shares\Banking`.
2. Disabled inheritance and converted permissions to explicit.
3. Stripped default `Users` group access (closing the default read leak).
4. Assigned `Modify` rights to Domain Local groups (`DL_AccountingModifier`, `DL_Banking`).
5. Created private nested subfolder `Banking\HR_PRIVATE` restricted exclusively to `HR_Private`. Verified with Effective Access tab.

### Section 4: Automated Drive Mapping via Group Policy Preferences (GPP)
- **Drive B: (Accounting):** Target `\DC01\Accounting`, Item-Level Targeting -> `LAB\GG_Accounting`
- **Drive K: (Banking):** Target `\DC01\Banking`, Item-Level Targeting -> `LAB\GG_Banking`

### Section 5: Workstation Baseline Security Policy
Workstations organized in `OU=Workstations` receive computer-level enforcement:
- Machine inactivity screen lock: 900 seconds (15 minutes).
- Authorized Users Only legal warning banner.
- Windows Defender Firewall enabled across Domain, Private, and Public profiles.
- Removable Storage Access lockdown: Deny all USB mass storage.

### Section 6: Centralized Wallpaper & The UNC Path Gotcha
Referencing a local path like `C:\Wallpaper\Team.jpg` in GPO causes client background screens to turn black because `C:\Wallpaper` does not exist on client hard drives. Path must be specified as a UNC share: `\DC01\Wallpaper\Team.jpg`.

### Section 7: Enterprise Web Browsing Restrictions via Edge Policy Templates
Central Store seeded at `\lab.local\SYSVOL\lab.local\Policies\PolicyDefinitions` with Edge ADMX templates:
- `URLBlocklist`: `*` (block all sites)
- `URLAllowlist`: `microsoft.com`, `bing.com`, `lab.local`, `edge://*` (allow approved sites)

---

## 5. Chapter 3: Enterprise Perimeter Security & Multi-Site Networking with pfSense

### Section 1: Architectural Evolution: From Flat Lab to Multi-Site Topology
The infrastructure transitions from a flat lab into an enterprise multi-site topology:
- **HQ Site:** LAN `192.168.10.0/24`, FW-HQ (LAN `192.168.10.1`, WAN `192.168.23.138`)
- **Branch Site:** LAN `192.168.20.0/24`, FW-Branch (LAN `192.168.20.1`, WAN `192.168.23.139`)
- **WAN Transit:** `192.168.23.0/24`, Gateway `192.168.23.2`

### Section 2: Deploying FW-HQ & Gateway Re-Addressing
FW-HQ console confirms `em0` (WAN: `192.168.23.138/24`) and `em1` (LAN: `192.168.10.1/24`). Pinging Branch WAN (`192.168.23.139`) initially fails due to default-deny WAN rules.

![Figure 15: FW-HQ Console & Interface Assignment](./images/image15.png)  
*Figure 15: FW-HQ Console & Interface Assignment — WAN (em0: 192.168.23.138/24) and LAN (em1: 192.168.10.1/24).*

DC01 Default Gateway is updated to `192.168.10.1`:

![Figure 16: DC01 Default Gateway Configuration](./images/image16.png)  
*Figure 16: DC01 Default Gateway Configuration — Pointing IPv4 Gateway to 192.168.10.1.*

Testing outbound connectivity through pfSense NAT:

![Figure 17: DC01 Internet Reachability Verification](./images/image17.png)  
*Figure 17: DC01 Internet Reachability Verification — ICMP replies from 8.8.8.8 over pfSense outbound NAT.*

### Section 3: Deploying FW-Branch & Branch Client Verification
FW-Branch interface assignment: `em0` (WAN: `192.168.23.139/24`) and `em1` (LAN: `192.168.20.1/24`).

![Figure 18: FW-Branch Console Interface Overview](./images/image18.png)  
*Figure 18: FW-Branch Console Interface Overview — WAN on em0 and LAN on em1.*

Windows 11 HQ Client verified with gateway `192.168.10.1`, pinging `8.8.8.8` and resolving `google.com`:

![Figure 19: HQ Client Network & Name Resolution Proof](./images/image19.png)  
*Figure 19: HQ Client Network & Name Resolution Proof — Verifying connectivity and DNS forwarder resolution.*

### Section 4: pfSense WebGUI Management & System Hardening
Web interface accessed via `https://192.168.10.1`:

![Figure 20: pfSense WebGUI Authentication Portal](./images/image20.png)  
*Figure 20: pfSense WebGUI Authentication Portal — Logging into FW-HQ.*

Setup Wizard defines Hostname `FW-HQ` and Domain `lab.local`:

![Figure 21: pfSense General Information Setup](./images/image21.png)  
*Figure 21: pfSense General Information Setup — Configuring FW-HQ.lab.local.*

Dashboard confirms AMD Ryzen 5 PRO 2500U processor and active AES-NI CPU cryptographic acceleration:

![Figure 22: FW-HQ System Dashboard & Cryptographic Status](./images/image22.png)  
*Figure 22: FW-HQ System Dashboard — System overview and hardware crypto acceleration status.*

### Section 5: Inter-Firewall Transit Rules & ICMP Telemetry
Creating an explicit pass rule on FW-HQ WAN interface for IPv4 ICMP Echo Requests:

![Figure 23: Creating WAN ICMP Inspection Rule](./images/image23.png)  
*Figure 23: Creating WAN ICMP Inspection Rule — Pass rule for ICMP Echo Request on WAN.*

![Figure 24: Active WAN Firewall Ruleset on FW-HQ](./images/image24.png)  
*Figure 24: Active WAN Firewall Ruleset on FW-HQ — Applied 'Allow Ping for Lab' rule.*

### Section 6: Branch Office Provisioning & Administrative Security
Branch PC verified against local gateway `192.168.20.1` and `8.8.8.8`:

![Figure 25: Branch PC Local & Internet Gateway Verification](./images/image25.png)  
*Figure 25: Branch PC Gateway Verification — Validating local branch subnet routing.*

FW-Branch WebGUI accessed at `https://192.168.20.1`:

![Figure 26: FW-Branch WebGUI Login Screen](./images/image26.png)  
*Figure 26: FW-Branch WebGUI Login Screen — Branch management portal.*

Setup Wizard executed for `FW-Branch.lab.local`:

![Figure 27: FW-Branch System Hostname Definition](./images/image27.png)  
*Figure 27: FW-Branch Hostname Setup — Onboarding FW-Branch.*

Hardening administrative password to `PFSense123!`:

![Figure 28: Admin Account Password Hardening](./images/image28.png)  
*Figure 28: Admin Password Hardening — Updating credential to PFSense123!.*

Applying WAN ICMP pass rule on FW-Branch:

![Figure 29: FW-Branch Active WAN Firewall Rules](./images/image29.png)  
*Figure 29: FW-Branch Active WAN Rules — Committing 'Allow ICMP for Lab'.*

### Section 7: Deep Packet Inspection & Diagnostic Verification
Packet Capture on FW-Branch `em0` (WAN) verifying bidirectional ICMP echo request/reply with upstream `192.168.23.2`:

![Figure 30: FW-Branch WAN Packet Capture Analysis](./images/image30.png)  
*Figure 30: FW-Branch WAN Packet Capture Analysis — Capturing live ICMP and UDP DNS packets on em0.*

Packet Capture on FW-HQ `em0` verifying stateful NAT translation:

![Figure 31: FW-HQ NAT Translation Packet Inspection](./images/image31.png)  
*Figure 31: FW-HQ NAT Translation Packet Inspection — Outbound UDP port 22616 translation to WAN IP.*

---

## 6. Chapter 4: Enterprise Identity Integration: Windows Server NPS (RADIUS) & pfSense AAA

### Section 1: The Centralized AAA Architecture
Firewalls should never maintain local user databases for remote workers. Centralized Authentication, Authorization, and Accounting (AAA) is brokered via RADIUS (UDP 1812) to Windows Server Network Policy Server (NPS) querying Active Directory DS.

### Section 2: Installing & Authorizing Network Policy Server in Active Directory
Installing NPAS on DC01:

![Figure 32: NPAS Role Installation Completion](./images/image32.png)  
*Figure 32: NPAS Role Installation Completion — Network Policy and Access Services deployed on DC.lab.local.*

Registering NPS in Active Directory:

![Figure 33: Authorizing NPS in Active Directory](./images/image33.png)  
*Figure 33: Authorizing NPS in Active Directory — Granting NPS permission to read user dial-in attributes.*

### Section 3: Registering pfSense as a RADIUS Client in NPS
Adding `pfSense-HQ` (`192.168.10.1`) with shared secret `Pass123`:

![Figure 34: RADIUS Client Definition in NPS](./images/image34.png)  
*Figure 34: RADIUS Client Definition in NPS — Registering pfSense-HQ with shared secret Pass123.*

### Section 4: Authoring the Enterprise Network Access Policy
Creating policy `VPN-Allow`:

![Figure 35: NPS Policy Creation: Name & Type](./images/image35.png)  
*Figure 35: NPS Policy Creation — Naming policy VPN-Allow.*

Setting condition to `LAB\Domain Users`:

![Figure 36: Selecting Policy Conditions: User Groups](./images/image36.png)  
*Figure 36: Selecting Policy Conditions — Choosing User Groups condition.*

![Figure 37: Configuring User Groups Condition](./images/image37.png)  
*Figure 37: Configuring User Groups Condition — Appending LAB\Domain Users.*

Setting access to `Access granted`:

![Figure 38: Specifying Access Permission](./images/image38.png)  
*Figure 38: Specifying Access Permission — Access granted.*

Restricting authentication strictly to `MS-CHAP-v2`:

![Figure 39: Enforcing MS-CHAP-v2 Cryptographic Authentication](./images/image39.png)  
*Figure 39: Enforcing MS-CHAP-v2 — Stripping insecure legacy ciphers.*

Completing and activating policy:

![Figure 40: Network Policy Completion Summary](./images/image40.png)  
*Figure 40: Network Policy Completion Summary — Policy settings overview.*

![Figure 41: Active Network Policy List with VPN Profile](./images/image41.png)  
*Figure 41: Active Network Policy List — VPN-Allow active in NPS console.*

### Section 5: Validating RADIUS AAA Integration from pfSense
Testing authentication under pfSense **Diagnostics > Authentication**:

![Figure 42: pfSense RADIUS Authentication Proof](./images/image42.png)  
*Figure 42: pfSense RADIUS Authentication Proof — User Administrator authenticated successfully against AD-DC-RADIUS.*

---

## 7. Chapter 5: Public Key Infrastructure (PKI) & Enterprise IKEv2 Mobile Client VPN

### Section 1: Establishing the Internal Certificate Authority (Lab-CA)
Creating internal root CA with RSA 2048-bit key and SHA256 digest:

![Figure 43: Creating Internal Certificate Authority (Lab-CA)](./images/image43.png)  
*Figure 43: Creating Internal CA — Instantiating Lab-CA.*

![Figure 44: Cryptographic Digest & Authority Parameters](./images/image44.png)  
*Figure 44: Authority Parameters — SHA256, 3650 days lifetime, CN=Lab-CA.*

![Figure 45: Active Certificate Authorities List](./images/image45.png)  
*Figure 45: Active Authorities List — Lab-CA active and valid through 2036.*

Exporting `Lab-CA.crt`:

![Figure 46: Exported Lab-CA.crt Certificate File](./images/image46.png)  
*Figure 46: Exported Lab-CA.crt — Ready for client trust store deployment.*

### Section 2: Generating the VPN Server Certificate (VPN-Server-Cert)
Creating server certificate signed by `Lab-CA`:

![Figure 47: Add/Sign Internal Server Certificate](./images/image47.png)  
*Figure 47: Add/Sign Server Certificate — Creating VPN-Server-Cert.*

Setting Common Name to WAN IP `192.168.23.138`:

![Figure 48: Server Certificate Cryptographic Parameters](./images/image48.png)  
*Figure 48: Server Certificate Parameters — CN set to 192.168.23.138.*

Enforcing Subject Alternative Name (SAN) Type: IP Address = `192.168.23.138` (Mandatory for Windows IKEv2 native client):

![Figure 49: Enforcing Server Certificate Type & IP SAN](./images/image49.png)  
*Figure 49: Enforcing SAN IP — Critical IP SAN configuration preventing Error 13801.*

### Section 3: Configuring IPsec Mobile Client Core Settings
Enabling mobile client support, assigning `AD-DC-RADIUS`, virtual pool `10.10.100.0/24`, search domain `lab.local`, and DNS `192.168.10.10`:

![Figure 50: Enabling Mobile Client Support & RADIUS AAA](./images/image50.png)  
*Figure 50: Enabling Mobile Client Support — Offloading authentication to RADIUS.*

![Figure 51: Virtual IP Pool & Domain Propagation](./images/image51.png)  
*Figure 51: Virtual IP Pool — Assigning 10.10.100.0/24 and lab.local domain.*

![Figure 52: Internal DNS Assignment (DC01)](./images/image52.png)  
*Figure 52: Internal DNS Assignment — Pushing DC01 IP (192.168.10.10).*

### Section 4: Authoring the IPsec Phase 1 Proposal (IKE SA)
Configuring IKEv2, WAN interface, EAP-RADIUS authentication, `VPN-Server-Cert`, AES 256-bit encryption, SHA256 hash, DH Group 14, NAT-T Auto, and MOBIKE Enabled:

![Figure 53: Phase 1 General & Endpoint Settings](./images/image53.png)  
*Figure 53: Phase 1 General Settings — IKEv2 on WAN.*

![Figure 54: Phase 1 Authentication & Cryptographic Suite](./images/image54.png)  
*Figure 54: Phase 1 Suite — EAP-RADIUS, VPN-Server-Cert, AES-256, DH14.*

![Figure 55: Advanced Parameters: NAT-T, MOBIKE & DPD](./images/image55.png)  
*Figure 55: Advanced Parameters — NAT-T Auto, MOBIKE enabled, DPD 10s.*

![Figure 56: Active Phase 1 Proposal Summary](./images/image56.png)  
*Figure 56: Active Phase 1 Proposal Summary — Overview in Tunnels list.*

### Section 5: Authoring the IPsec Phase 2 Proposal (Child IPsec SA)
Configuring Tunnel IPv4, Local Network: `LAN subnet` (`192.168.10.0/24`), Protocol: ESP, AES 256 / AES-GCM 128, Lifetime 3600s, Rekey 3240s:

![Figure 57: Phase 2 Network Selector Definition](./images/image57.png)  
*Figure 57: Phase 2 Network Selector — LAN subnet destination.*

![Figure 58: Phase 2 ESP Cryptographic Suite](./images/image58.png)  
*Figure 58: Phase 2 Suite — ESP protocol with AES-256 and SHA256.*

![Figure 59: Phase 2 SA Lifetime & Rekey Parameters](./images/image59.png)  
*Figure 59: Phase 2 Rekey Parameters — 3600s lifetime, 3240s rekey.*

![Figure 60: Completed IPsec Tunnels Configuration Overview](./images/image60.png)  
*Figure 60: Completed IPsec Tunnels Overview — Phase 1 and Phase 2 active.*

### Section 6: State-Enforced Firewall Rules for IPsec
- **WAN Interface Rule:** Pass IPv4 UDP from Any to WAN address on Ports `500` (ISAKMP) and `4500` (NAT-T).
- **IPsec Interface Rule:** Pass IPv4 Any from Source Network `10.10.100.0/24` to Destination `LAN subnets` (`192.168.10.0/24`).

![Figure 61: Creating WAN Inbound Rule for IPsec Handshake](./images/image61.png)  
*Figure 61: WAN Handshake Rule — Pass UDP on WAN.*

![Figure 62: Port Range Assignment: UDP 500 to 4500](./images/image62.png)  
*Figure 62: Destination Ports — 500 to 4500 into WAN address.*

![Figure 63: Authorizing Decapsulated IPsec Traffic](./images/image63.png)  
*Figure 63: Decapsulated Traffic Rule — Source network 10.10.100.0/24.*

![Figure 64: Destination Binding: LAN Subnets](./images/image64.png)  
*Figure 64: Destination LAN Subnets — Authorizing access into AD network.*

![Figure 65: Active IPsec Firewall Rules Table](./images/image65.png)  
*Figure 65: Active IPsec Firewall Rules Table — Committed pass rule for virtual client pool.*

---

## 8. Chapter 6: Next-Generation Zero-Trust Remote Access: Tailscale Mesh Subnet Router

### Section 1: Deploying the Tailscale Package on pfSense
Installing `pfSense-pkg-Tailscale` (v0.1.10 / WireGuard v1.98.5):

![Figure 66: Tailscale Package Selection in pfSense](./images/image66.png)  
*Figure 66: Tailscale Package in Manager — Package selection.*

![Figure 67: Package Installation Success](./images/image67.png)  
*Figure 67: Package Installation Success — Daemon installed and interface group registered.*

### Section 2: Configuring Tailscale & Subnet Route Advertisement
Enabling service on UDP port 41641 and advertising internal route `192.168.10.0/24`:

![Figure 68: Tailscale General Settings & Daemon State](./images/image68.png)  
*Figure 68: Tailscale General Settings — Service enabled on port 41641.*

![Figure 69: Configuring Advertised Subnet Route (192.168.10.0/24)](./images/image69.png)  
*Figure 69: Advertised Subnet Route — Advertising 192.168.10.0/24.*

### Section 3: Authenticating the Node via pfSense CLI
Executing CLI route advertisement and node authentication:
```bash
tailscale up --advertise-routes=192.168.10.0/24
```

![Figure 70: CLI Route Advertisement & Node Activation](./images/image70.png)  
*Figure 70: CLI Route Advertisement — Initializing node on pfSense shell.*

GUI confirms active daemon:

![Figure 71: Tailscale Status: Online Confirmation](./images/image71.png)  
*Figure 71: Tailscale Online Status — Service reporting online.*

### Section 4: Tailscale Admin Console Route Approval
Node `fw-hq` (`100.115.4.8`) approved for subnet route `192.168.10.0/24`:

![Figure 72: Approving Subnet Route in Tailscale Admin Portal](./images/image72.png)  
*Figure 72: Approving Subnet Route — Authorizing 192.168.10.0/24 in admin console.*

### Section 5: pfSense Firewall Policy for Tailscale Traffic
Committing pass rule on Tailscale interface to LAN subnets:

![Figure 73: Tailscale Interface Firewall Ruleset](./images/image73.png)  
*Figure 73: Tailscale Firewall Rule — Authorizing inbound mesh traffic to AD LAN.*

### Section 6: External Client Connection & RDP Management Verification
External Windows client (`DESKTOP-LBL51L9`) connects to Tailnet:

![Figure 74: External Client Authentication into Tailnet](./images/image74.png)  
*Figure 74: External Client Authentication — Adding client to Tailnet.*

Enabling Remote Desktop on DC01:

![Figure 75: Enabling Remote Desktop on Domain Controller (DC01)](./images/image75.png)  
*Figure 75: Enabling Remote Desktop on DC01 — System properties remote access.*

Testing reachability from external client:
```powershell
Test-NetConnection -ComputerName 192.168.10.10 -Port 3389
```

![Figure 76: Cross-Subnet RDP Port Verification over Tailscale](./images/image76.png)  
*Figure 76: RDP Socket Test — TcpTestSucceeded: True against 192.168.10.10:3389 from Tailscale IP 100.106.74.113.*

Launching Remote Desktop session:

![Figure 77: RDP Domain Authentication Prompt](./images/image77.png)  
*Figure 77: RDP Domain Credentials — Signing in as Administrator@lab.local.*

![Figure 78: RDP Security Certificate Validation](./images/image78.png)  
*Figure 78: RDP Certificate Validation — Trusting DC.lab.local.*

![Figure 79: Active Remote Management Session on DC01](./images/image79.png)  
*Figure 79: Active Remote Management Session on DC01 — Fully connected Server Manager session over Tailscale Subnet Router.*

---

## 9. Chapter 7: Endpoint Security, Client Trust & Certificate Store Management

### Section 1: Inspecting the Untrusted Certificate State
Windows client inspecting `Lab-CA.crt` displays untrusted root warning:

![Figure 80: Untrusted Root CA Certificate Warning](./images/image80.png)  
*Figure 80: Untrusted Root Certificate Warning — Lab-CA untrusted by default.*

### Section 2: Deploying the Root CA via the Certificate Import Wizard
Opening Certificate Import Wizard and selecting manual store placement:

![Figure 81: Certificate Store Manual Selection](./images/image81.png)  
*Figure 81: Certificate Store Manual Selection — Overriding automatic placement.*

Selecting **Trusted Root Certification Authorities**:

![Figure 82: Selecting Trusted Root Certification Authorities](./images/image82.png)  
*Figure 82: Selecting Trusted Root Store — Choosing the operating system trust root.*

Finalizing import:

![Figure 83: Certificate Import Wizard Finalization](./images/image83.png)  
*Figure 83: Certificate Import Wizard Finalization — Successful root anchor installation.*

### Section 3: Enterprise Automated Certificate Distribution
- **Active Directory Group Policy (GPO):** `Computer Configuration > Windows Settings > Security Settings > Public Key Policies > Trusted Root Certification Authorities`
- **Microsoft Intune / MDM:** Trusted Certificate Configuration Profiles pushed to non-domain mobile devices.

---

## 10. Chapter 8: Comprehensive Troubleshooting Field Guide & Enterprise Takeaways

### Section 1: The Unified 4-Layer Diagnostic Methodology
1. **Layer 1: Socket / Transport:** `Test-NetConnection -Port <X>`, `ping`, `tracert`
2. **Layer 2: Name Resolution (DNS):** `nslookup <FQDN>`, `ipconfig /displaydns`
3. **Layer 3: Authentication & AAA:** NPS Security Event Logs (`Event ID 6273/6272`), pfSense Auth Test
4. **Layer 4: Application & Policy:** Effective Access tab, `gpresult /r /scope user / computer`

### Section 2: Master Diagnostic & Failure Resolution Matrix

| Symptom / Error State | Technical Root Cause | Step-by-Step Remediation Strategy |
| :--- | :--- | :--- |
| **Mail stuck in Outbox; domain logons fail intermittently.** | Dual-homed VM has both LAN Segment and NAT adapters. NAT adapter owns default gateway; Windows queries NAT DNS for `lab.local`. | Lower LAN adapter metric to 10; raise NAT to 50 via `Set-NetIPInterface`. Untick 'Register this connection's addresses in DNS' on NAT adapter. Run `ipconfig /flushdns`. |
| **pfSense WAN ping returns 100% packet loss.** | pfSense enforces stateful default-deny on unsolicited incoming WAN traffic. | Navigate to **Firewall > Rules > WAN**. Create pass rule for Protocol: ICMP, Subtype: Echo Request, Destination: WAN address. |
| **RADIUS authentication timeout or Access-Reject.** | Shared secret mismatch in NPS RADIUS client, or NPS server not registered in Active Directory. | Verify shared secret matches on both ends (`Pass123`). Open `nps.msc`, right-click NPS (Local) > 'Register server in Active Directory'. Check Event Viewer Security Log. |
| **Windows IKEv2 VPN fails with Error 13801.** | Server certificate lacks external WAN IP in Subject Alternative Name (SAN), or Root CA not installed in Trusted Root store. | Regenerate server certificate with SAN Type: IP Address = `192.168.23.138`. Import `Lab-CA.crt` into client's 'Trusted Root Certification Authorities' store. |
| **Tailscale CLI reports 'invalid key: API key does not exist'.** | Tailscale node initialized without authentication authkey or pending browser login. | Run `tailscale up --advertise-routes=192.168.10.0/24`, complete interactive browser authentication, and approve route in Tailscale Admin Console. |
| **GPO Wallpaper displays blank / black background.** | GPO configured with local path (`C:\Wallpaper\Team.jpg`) which does not exist on client C: drives. | Store image in a shared folder (`\DC01\Wallpaper\Team.jpg`) with Authenticated Users (Read). Update GPO path to UNC format. |
| **Edge browser URL Allowlist blocks internal pages.** | `URLBlocklist = *` aggressively catches internal browser schemes. | Add `edge://*` and `chrome://*` explicitly to the `URLAllowlist` policy. |

### Section 3: Enterprise Hardening & Architectural Next Steps
1. **Dedicated Messaging:** Transition from hMailServer to Microsoft 365 / Exchange Online with Entra Connect.
2. **High Availability Domain Services:** Deploy secondary Domain Controller (`DC02`) for replication and FSMO redundancy.
3. **Enterprise PKI Tiering:** Two-tier Active Directory Certificate Services (AD CS) with offline root and online issuing CA.
4. **802.1X Network Access Control:** Deploy dynamic VLAN assignment and EAP-TLS certificate-based device access via NPS.
5. **Centralized SIEM:** Ingest pfSense syslog and Windows Security event logs into Wazuh or Microsoft Sentinel.

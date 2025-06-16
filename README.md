# snort-lab-setup
# 🛡️ Snort IDS Lab Setup (Ubuntu + Kali)

This project sets up a simple **Intrusion Detection System (IDS)** using **Snort** on an Ubuntu machine to detect `ping` and `SSH` traffic from a Kali attacker machine.

## 🧪 Lab Environment

| System       | Role                    | Interface | IP Address       |
|--------------|-------------------------|-----------|------------------|
| Ubuntu       | Snort IDS               | enp0s8    | 192.168.92.11    |
| Kali Linux   | Attacker/Test Machine   | same LAN  | 192.168.92.X     |

## 🧰 Installation (on Ubuntu)

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install snort -y
```

During install:
- Network Interface: `enp0s8`
- HOME_NET: `192.168.92.0/24`

## 🛠️ Configuration

### 🔹 Edit `snort.conf`

```bash
sudo nano /etc/snort/snort.conf
```

Set HOME_NET:
```snort
var HOME_NET 192.168.92.0/24
```

Ensure this line is enabled:
```snort
include $RULE_PATH/local.rules
```

### 🔹 Add Custom Rules

```bash
sudo nano /etc/snort/rules/local.rules
```

Paste the following:
```snort
# Detect ping
alert icmp any any -> any any (msg:"[Snort] ICMP Ping Detected"; sid:1000001; rev:1;)

# Detect SSH
alert tcp any any -> any 22 (msg:"[Snort] SSH Connection Attempt"; sid:1000002; rev:1;)
```

## 🚀 Run Snort in IDS Mode

```bash
sudo snort -A console -q -c /etc/snort/snort.conf -i enp0s8
```

## 💣 Attack from Kali

```bash
ping 192.168.92.11
ssh 192.168.92.11
```

## 📺 Expected Output

```
[**] [1:1000001:1] [Snort] ICMP Ping Detected [**]
[**] [1:1000002:1] [Snort] SSH Connection Attempt [**]
```

## 📦 Optional Extensions

- Detect Nmap scans
- Log alerts to files
- Turn Snort into IPS mode using iptables

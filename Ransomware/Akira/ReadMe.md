# 🛡️ Akira Ransomware Detection Blueprint - Podzahr Podcast

This directory contains the production-ready configuration files to hunt and mitigate **Akira Ransomware** using **Microsoft Sysmon** and **Wazuh XDR/SIEM**.

## 🚀 How to Deploy in a 300+ Endpoint Environment:

1. **Sysmon Deployment:**
   Deploy the `sysmon-config-akira.xml` via Active Directory GPO Startup Script:
   ```cmd
   Sysmon64.exe -acceptEula -i sysmon-config-akira.xml

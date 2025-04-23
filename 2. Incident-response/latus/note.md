Sherlock Scenario

Our customer discovered illegal RDP sessions without Privileged Access Management (PAM) in their system on June 28. They collected evidence on a server they suspected was an intermediary server to move laterally to others. Even though the attacker deleted the event log, I believe the few remaining artifacts are enough to help confirm the attack flow and trace the attacker's behavior.
latus.zip
899 MB

# When was the last failed logon attempt using emman.t user? (UTC)
2024-06-26 07:24:35 ( using system32 config folder sam hive log)

# What are the first 3 IP addresses that emman.t connected to using Remote Desktop (RDP)?
192.168.86.250,192.168.25.128,192.168.25.131 ( in SAM hive)

# What is the destination username used to remote desktop to for the first time on 2024-06-20 16:01:05 UTC?
tommyxiaomi (in same SAM hive)

# What is the destination IP address of the last Remote Desktop (RDP) session?
192.168.70.133 (in same SAM hive)

# emman.t is very careless in always saving RDP credentials to connect to other hosts, so we believe that attacker somehow leaked them. Please confirm credentials of the server with ip 192.168.70.133 that was leaked?
first find password for emman as `emman2024` then using dpapi to get `Administrator : C@mv@0s3rv3r`


# When was the last time the Remote Desktop Connection application was executed? (UTC)
2024-06-28 13:56:48 (seach using prefetch)

# When was the last time the Remote Desktop Connection application was terminated? (UTC)
2024-06-28 14:01:26 (search in system bam hive)

# How long did the penultimate RDP session last?
4 min 38 sec

# When did the attacker disconnect the last Remote Desktop (RDP) session? (UTC)
28 ?June ?2024, ??19:21:03

# What is the size of the remote desktop configured?
1920:1080

# What tool did attacker use to discover the network after moving laterally to 192.168.70.133?

# When was the event log deleted by the attacker? (UTC)

# What time did attacker disconnect session to 192.168.70.129? (UTC)

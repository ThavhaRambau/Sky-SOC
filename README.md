# Sky-SOC
Hacker Portal — How It Works
You make three choices before launching an attack:

Pick a target — five simulated systems (web server, database, domain controller, jump host, finance workstation). Each has different services running, so not every attack applies to every target. SQL injection only makes sense against a web or DB server, for example.
Pick a category and attack — five categories (Recon, Exploitation, Credential Attacks, Lateral Movement, Persistence), each with specific tools. Attacks grayed out are incompatible with your chosen target.
Hit Launch — the terminal runs a simulated output, line by line with timing delays to feel realistic. No real network traffic is sent — it's all scripted strings that look like real tool output.

After the animation, the engine rolls a probability based on the attack's stealth level (shown as dots, 1–5). A low-stealth attack like an Nmap scan is almost always caught. A high-stealth one like Pass-the-Hash has a real chance of slipping through undetected. The result is one of three outcomes: Detected, Blocked, or Ghost (undetected).

SOC Portal — How It Responds
If the attack is detected, three things happen simultaneously:

A red badge and pulsing dot appear on the SOC tab button so you can see there's activity without switching portals
An alert drops into the live feed on the Dashboard
An incident card is created in Active Incidents
A SAST/Detection Engine entry is created showing the exact IDS/SIEM rule that fired, the matched payload evidence, why it's a threat, and recommended response steps

The Detection Engine view is the most educational part — it shows you what a real SIEM like Splunk or Sentinel would display, including rule IDs (like IDS-2100014 for port scans or WAF-SQLI-0023 for SQL injection).

The Response Flow
When you switch to the SOC Portal and respond to an incident:

Click Respond on an incident card
Choose which actions you took (Isolate Host, Block IP, etc.)
Set a disposition (Contained, Escalated, False Positive, Monitoring)
Write analyst notes
Click File Report — the incident moves from Active Incidents to the Reports tab

At any point, Export Report .txt generates a full formatted report file covering everything: detection signatures, analyst responses, undetected attacks (your security gaps), and remediation recommendations.
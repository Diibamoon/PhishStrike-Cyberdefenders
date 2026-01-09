# PhishStrike-Cyberdefenders
Week 10 - Lab Task Social Engineering - Blue Team

## Introduction
PhishStrike is a blue team phishing investigation challenge that focuses on analyzing a malicious email used as an initial access vector. This write-up documents the process of identifying phishing indicators, understanding attacker techniques, and evaluating potential impact from a defensive cybersecurity perspective.

---

## Objectives
- To analyze a phishing email sample
- To identify indicators of phishing
- To understand social engineering techniques used by attackers
- To recommend defensive mitigation strategies

---

## Environment
- Platform: CyberDefenders
- Challenge: PhishStrike
- Analysis Type: Phishing Email Investigation
- Role: Blue Team

---

## Phishing Email Overview
The provided email sample is designed to deceive the recipient into interacting with malicious content. The email attempts to appear legitimate while exploiting human trust and urgency to initiate the attack.

Key elements analyzed include sender information, message content, and user interaction requests.

---

## Phishing Indicators Identified

### 1. Suspicious Sender Information
The sender’s email address does not match the legitimate organization it claims to represent. This indicates possible impersonation.

---

### 2. Social Engineering Techniques
The email uses urgency and authority to pressure the recipient into taking immediate action, a common phishing tactic.

---

### 3. Suspicious Link or Interaction
The message encourages the user to click a link or respond to the email, which may lead to credential harvesting or further compromise.

---

### 4. Inconsistent Email Characteristics
The email contains unusual formatting and misleading content that deviates from legitimate organizational communication.

---

## Attack Classification
- Attack Type: Phishing
- Technique: Social Engineering
- MITRE ATT&CK Tactic: Initial Access (T1566 – Phishing)

---

## Potential Impact
If a victim interacts with the phishing email, the possible impact includes:
- Credential theft
- Unauthorized access to user accounts
- Further security compromise
- Data leakage or financial loss

---

## Defensive Recommendations
- Verify sender email addresses and domains
- Avoid interacting with suspicious emails
- Implement email filtering and phishing detection
- Conduct regular user awareness training
- Enforce email authentication mechanisms (SPF, DKIM, DMARC)

---

## Conclusion
The PhishStrike challenge demonstrates how phishing remains an effective attack vector due to human factors rather than technical vulnerabilities. Proper analysis and awareness are essential in identifying and mitigating phishing threats.

---

## References
- CyberDefenders – PhishStrike
- MITRE ATT&CK Framework (T1566 – Phishing)
- Mxtoolbox
- URLhaus
- Virustotal
- Malwarebazaar
- Any Run
- CyberChef
- Tri.age

---

## Screenshots

1.MxTOOLBOX
Mxtoolbox is an online dignostic tool that use to check and troubleshoot email,DNS and domain-related issues. We need to put all the details content and it will show the result of the email.
<img width="1918" height="932" alt="LabW10 - PhiserTrike" src="https://github.com/user-attachments/assets/b7dd0909-0c64-49c1-b508-46efee0b9a1c" />
<img width="1897" height="825" alt="LabW10 - PhiserTrike1" src="https://github.com/user-attachments/assets/b2018163-2a36-4baf-9179-ea04f73c3f48" />
<img width="1903" height="825" alt="LabW10 - PhiserTrike2" src="https://github.com/user-attachments/assets/e4eb388e-03b5-4bee-86cf-26b7eb58fe53" />
<img width="1902" height="826" alt="LabW10 - PhiserTrike3" src="https://github.com/user-attachments/assets/286199cf-bf93-4346-bc13-c2637edd25cb" />

2. URLHaus
URLhaus is a public threat intelligence platform used to collect, track, and share information about malicious URLs that are actively used to distribute malware. Here show that some of the URL Tags with AsyncRAT, bitrat and CoinMiner.
<img width="1902" height="867" alt="LabW10 - PhiserTrike4" src="https://github.com/user-attachments/assets/9892ba84-f0b9-4115-8972-1d53be8d10cf" />


4. VirusTotal
VirusTotal is an online security platform used to analyze files, URLs, IP addresses, and domains to determine whether they are malicious.
<img width="1902" height="962" alt="LabW10 - PhiserTrike5" src="https://github.com/user-attachments/assets/bd5078b1-cacc-49bc-a5a7-7aa611558373" />
<img width="1897" height="867" alt="LabW10 - PhiserTrike6" src="https://github.com/user-attachments/assets/3120b403-fa64-461c-abab-a7612acc0035" />


6. MalwareBazaar
MalwareBazaar is a threat intelligence platform used to collect, share, and analyze malware samples.
<img width="1898" height="867" alt="LabW10 - PhiserTrike7" src="https://github.com/user-attachments/assets/cceea4b7-e9c5-4952-bc4f-f80dd2424940" />

7. ANY.RUN
ANY.RUN is an interactive online malware sandbox used to analyze suspicious files and URLs in real time. Its allow analysts to interact with malware while its running. You also can click buttons, enter input and observe behavior live.
<img width="1918" height="967" alt="LabW10 - PhiserTrike8" src="https://github.com/user-attachments/assets/8fcf8aaa-15e0-44fe-963b-ba932fc1a234" />
<img width="1912" height="855" alt="LabW10 - PhiserTrike9" src="https://github.com/user-attachments/assets/35f9cf93-7212-4741-b5ca-69b663efb1c1" />

8. CyberChef
CyberChef is a web-based tool used to analyze, decode, encode, and transform data during cybersecurity investigations. You can put the input and choose recipe which is sequence of operations that you apply step-by-step to data in order to decode, analyze or tranform it.
<img width="1912" height="963" alt="LabW10 - PhiserTrike10" src="https://github.com/user-attachments/assets/4d22dc73-56e3-4e15-a444-8afccbaddf42" />

9. Tri.age
10. Triage is an automated malware analysis platform used to analyze suspicious files and URLs and determine their malicious behavior. It helps analysts understand what the malware actually does, also it provide risk scores and indicators.
<img width="1877" height="956" alt="LabW10 - PhiserTrike11" src="https://github.com/user-attachments/assets/1f04c345-d1e0-48a1-9cb7-a614cf525f89" />




# SOC146 - Phishing Mail Detected (Excel 4.0 Macros)

## 🕵️‍♀️ Incident Summary

An alert was triggered in the SOC for a **phishing email** containing a **ZIP attachment** with embedded **Excel 4.0 (XLM) macro** and suspicious DLL payloads. 
This alert was titled **"SOC146 - Phishing Mail Detected - Excel 4.0 Macros"**.

The investigation involved:
- Reviewing email metadata
- Extracting and analyzing file attachments
- Executing files in a sandbox environment (AnyRun)
- Verifying malicious indicators using VirusTotal
- Checking for user interaction and endpoint execution
- Containing the affected host and documenting all artifacts
  
---

## 📩 Email Analysis

| Question                            | Answer                                                                   |
|-------------------------------------|--------------------------------------------------------------------------|
| **When was it sent?**               | Jun, 13, 2021, 02:13 PM                                                  |
| **What is the SMTP address?**       | 24.213.228.54                                                            |
| **What is the sender address?**     | trenton@tritowncomputers.com                                             |
| **What is the recipient?**          | lars@letsdefend.io                                                       |
| **Is the mail content suspicious?** | Yes — the language is vague and urges quick action regarding an invoice. |
| **Are there any attachments?**      | Yes                                                                      |

The email urged the recipient to view an invoice and included a Microsoft Excel file as an attachment. Due to the presence of Excel 4.0 macros, further inspection was needed.

---

## 🧪 Malware Analysis: Extracted Files from ZIP Attachment

These files were extracted from a malicious ZIP attachment during an ANY.RUN sandbox session. Each was individually uploaded to [VirusTotal](https://www.virustotal.com/) **within the sandbox environment**, and the following details were recorded.

---

### 📥 Original ZIP Attachment

- **File Name:** (11f44631fb088d31307d87b01e8eabff.zip)
- **Sandbox Used:** [ANY.RUN](https://any.run/)
- **Analysis Summary:** The ZIP contained the above files, which were individually tested in a sandbox environment. They showed multiple detections from major antivirus vendors and were flagged as malicious.

---

### 🗂 File: `iroto1.dll`

- **MD5 Hash:** *8e6fbefcbac2a1967941fa692c82c3ca* (provided by VirusTotal upon upload)
- **VirusTotal Detection:** **12/72**
- **Common AV Labels:**
  - MALICIOUS (DeepInstinct)
  - Win32:Evo-gen[Trj] (Avast/AVG)
  - Trojan.Malware.3411146.susgen (MaxSecure)

---

### 🗂 File: `iroto.dll`

- **MD5 Hash:** *e03bde4862d4d93ac2ceed85abf50b18* (provided by VirusTotal upon upload)
- **VirusTotal Detection:** **13/72**
- **Common AV Labels:**
  - Unsafe (Arctic Wolf)
  - MALICIOUS (DeepInstinct)
  - W32.AIDetectMalware (Bkav Pro)

---

### 🗂 File: `research-1646684671.xls`

- **MD5 Hash:** *b775cd8be83696ca37b2fe00bcb40574* (provided by VirusTotal upon upload)
- **VirusTotal Detection:** **38/61**
- **Common AV Labels:**
  - VBS:Malware-gen (Avast/AVG)
  - Trojan.Generic.D2C53FCC (Arcabit)
  - Trojan:MSOffice/Downloader.amd (AliCloud)

---

## 🛡️ Outcome & Final Actions

| Action                                 | Status            |
|----------------------------------------|-------------------|
| Email Delivered                        | ✅ Yes            |
| Malicious Attachments Confirmed        | ✅ Yes            |
| User Opened File                       | ✅ Yes            |
| Host Contained                         | ✅ Yes            |
| Artifacts Added                        | ✅ Yes            |
| Case Closed                            | ✅ True Positive  |

---

## 🧠 MITRE ATT&CK Mapping

| Tactic         | Technique                       | Description                                        |
|----------------|----------------------------------|----------------------------------------------------|
| Initial Access | T1566.001 - Phishing: Spearphishing Attachment | Malicious XLS file with embedded XLM macro sent via email |
| Execution      | T1203 - Exploitation for Client Execution | Execution of macros via Excel                     |
| Command & Control | T1071.001 - Application Layer Protocol: Web | C2 communication observed in sandbox logs          |

---

## 📂 Investigation Steps (Playbook Walkthrough)

1. **Took ownership** of the alert in the Incident Monitoring page.
2. Reviewed incident metadata (event ID, timestamps, sender/recipient, etc.).

![Investigation Channel](letsdefend/images/1-investigation-channel.png)

![Incident Details](letsdefend/images/2-incident-details.png)

3. Identified a **ZIP attachment** from Email Security linked to the sender address.

![Email Security](letsdefend/images/3-email-security.png)

![Are There Attachments or URLs in the Email?](letsdefend/images/4-playbook.png)

4. Extracted ZIP contents in AnyRun and analyzed the three embedded files.
   - Confirmed **Excel 4.0 macros** execution.
  
![Analyze Url/Attachment](letsdefend/images/10-malicious.png)

![AnyRun](letsdefend/images/5-anyrun.png)

![Infected](letsdefend/images/6-anyrun.png)

5. Uploaded all 3 files to **VirusTotal**:
   - All files were confirmed **malicious** by multiple AV engines.

![iroto1.dll](letsdefend/images/7-virustotal.png)

![iroto.dll](letsdefend/images/8-virustotal.png)

![research-1646684671.xls](letsdefend/images/9-virustotal.png)
   
6. Verified that the email was **delivered** to the user.
     
![Check if Mail Delivered to User?](letsdefend/images/11-mail-delivered.png)

7. Checked **Log Management** and confirmed the user **opened** the malicious attachment:
   - Observed connection to **command and control (C2) URLs**.
   - Matching event logs showed requests to malicious URLs.

![Device Action: Allowed](letsdefend/images/12-device-action-allowed.png)

![Delete Email From Recipient](letsdefend/images/13-delete-email.png)

![Check if Someone opened the Malicious File/URL?](letsdefend/images/14-check-if-opened-notopened.png)

![Endpoint Information](letsdefend/images/15-endpoint-lars-ip.png)

![Log Management](letsdefend/images/16-log-management.png)

![Log Event 1](letsdefend/images/17-log-event1.png)

![Log Event 2](letsdefend/images/18-log-event2.png)

8. Used **Endpoint Security** to contain the host machine (Hostname: LarsPRD).

![Containment](letsdefend/images/19-containment.png)

![EDR Containment](letsdefend/images/20-edr-containment.png)

9. Documented and added the following as **Artifacts**:
    - 2 Malicious URLs
    - Sender email 
    - SMTP address
    - MD5 hashes of all 3 files

![Add Artifacts](letsdefend/images/21-add-artifacts.png)

![Finish Playbook](letsdefend/images/22-finish-playbook.png)

10. Finalized notes and **closed the case as True Positive**.

![Close Alert](letsdefend/images/23-close-alert.png)

---

## 🧾 Notes

This was a well-constructed phishing attempt using embedded Excel macros and DLL payloads. The attack was **successfully mitigated**, and indicators were **contained and documented**.

All findings were validated using third-party tools and the LetsDefend platform's investigation framework.






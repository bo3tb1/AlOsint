# AlOsint — Legal and Acceptable Use

**Status:** Draft for counsel review  
**Applies to:** AlOsint V1.0 and all later versions unless superseded  
**Last updated:** 2026-11-11

---

## IMPORTANT NOTICE

**AlOsint is provided for lawful, authorized, and ethical use only.**

**You may use AlOsint only on systems, domains, networks, and data that you own or for which you have explicit, documented permission from the person or organization authorized to grant it. Using AlOsint to access, collect, or analyze information about a system without authorization may be a criminal offense and a civil wrong in your jurisdiction.**

**This document is not legal advice. It does not create an attorney-client relationship. Laws differ by country, state, and circumstance. Consult a qualified lawyer before using AlOsint in any situation where you are unsure of your rights or obligations.**

By installing, running, or distributing AlOsint, you represent that you have read, understood, and agreed to this document. If you do not agree, do not use the software.

---

## 1. Purpose of This Document

This document sets out the legal and ethical boundaries for AlOsint. It is a condition of use, not a suggestion. It covers:

1. Authorized use only.
2. The prohibition on scanning without permission.
3. The boundaries of optional Tor usage.
4. The prohibition on harvesting leaked, breached, or illicitly obtained data.
5. Privacy, data protection, and third-party terms.
6. Disclaimers, limitation of liability, and indemnity.

Where this document conflicts with a mandatory rule of applicable law, the law prevails. Where it is stricter than the law, this document governs your use of AlOsint.

---

## 2. Authorized Use Only

### 2.1 The core rule

AlOsint collects information from public sources and makes ordinary network requests. Even so, **collection can be regulated**, and the consequences of misuse fall on you, not on the project.

You may use AlOsint only when **all** of the following are true:

1. You own the target, **or** you have prior, explicit, documented authorization from a party with the legal authority to grant it.
2. Your use falls within the scope of that authorization, including the specific domains, IP ranges, time window, and methods permitted.
3. Your use complies with all applicable laws, regulations, contracts, and terms of service.
4. Your use complies with this document.

### 2.2 What "documented authorization" means

Authorization should be in writing and should identify:

- The authorized party and the person granting permission.
- The exact targets, including domains, subdomains, and IP ranges.
- The permitted activities, including passive collection and any HTTP requests.
- The permitted time window.
- Any restrictions, such as excluded hosts or prohibited data types.
- A contact for escalation if something goes wrong.

A bug bounty program's published scope may constitute authorization **only** to the extent the program expressly says so, and only within its stated rules. A public website, an open port, or a lack of technical protection is **not** authorization.

### 2.3 Your representations

By using AlOsint, you represent and warrant that:

- You have the legal capacity to accept this document.
- You have all necessary authorizations for each target you query.
- You will stop immediately if you learn that your authorization is absent, expired, or narrower than you assumed.
- You will not use AlOsint on behalf of a client or employer without confirming that the engagement permits it.
- You are not subject to sanctions or export restrictions that prohibit your use of the software.

---

## 3. No Scanning Without Permission

### 3.1 Absolute prohibition

**Do not use AlOsint to scan, enumerate, fingerprint, or otherwise probe any system without authorization.** This applies even to "passive" features, because aggregating public data about a target can still cause harm, violate privacy, or breach contract or platform terms.

Prohibited conduct includes, without limitation:

- Enumerating DNS records, subdomains, or certificates for a domain you do not own and are not authorized to assess.
- Querying WHOIS, RDAP, or certificate transparency logs to build a profile of a person or organization for an unauthorized purpose.
- Sending HTTP requests to hosts you are not authorized to contact, including automated fingerprinting.
- Using AlOsint to prepare for unauthorized access, exploitation, or denial of service.
- Using AlOsint to circumvent technical access controls, terms of service, or rate limits imposed by a target or data source.
- Using AlOsint for stalking, harassment, doxxing, intimidation, or any form of targeting of individuals.
- Using AlOsint to make decisions about individuals in employment, housing, credit, insurance, education, healthcare, or access to essential services without a lawful basis and required disclosures.

### 3.2 Legal exposure

Unauthorized access, collection, or interference with computer systems is restricted or prohibited by laws in many jurisdictions, including but not limited to:

- The Computer Fraud and Abuse Act (United States).
- The Computer Misuse Act (United Kingdom).
- The Criminal Code provisions on unauthorized use of computers (Canada).
- The Directive on attacks against information systems and related national implementations (European Union).
- Equivalent computer misuse, privacy, and data protection laws in other countries and states.

This list is illustrative, not exhaustive. **A single unauthorized query can constitute an offense.** Civil liability, contractual claims, and regulatory penalties may also apply.

### 3.3 Minors and vulnerable persons

Do not use AlOsint to collect information about minors or other vulnerable persons except where you have a clear lawful basis and appropriate safeguards. Never use it to locate, contact, or profile an individual for harmful purposes.

---

## 4. Acceptable Use

Permitted uses include, subject to authorization and law:

- Assessing your own organization's public footprint.
- Authorized security assessments, penetration tests, and red team engagements within a defined scope.
- Incident response and threat intelligence work on indicators you are authorized to investigate.
- Academic or journalistic research using public data, with appropriate ethical review and minimization.
- Bug bounty and vulnerability disclosure work strictly within a program's published scope and rules.
- Compliance, due diligence, and asset inventory for domains and networks you control.

Even for permitted uses, you must:

- Respect rate limits and avoid causing degradation or undue load.
- Use only the minimum data necessary for your purpose.
- Avoid collecting personal data unless it is necessary and lawful.
- Keep records that demonstrate your authorization and scope.
- Stop and seek advice if a target's status or your authorization is unclear.

---

## 5. Tor Usage Boundaries

### 5.1 What `--tor` does

AlOsint offers an optional `--tor` flag that routes supported outbound HTTP(S) requests through a SOCKS5 proxy, typically a local Tor client. It is a **transport option**, not a legal shield, an authorization, or a guarantee of anonymity.

### 5.2 Tor does not authorize anything

Using Tor does not:

- Grant permission to access any system or data.
- Expand the scope of any authorization you hold.
- Make an otherwise unlawful act lawful.
- Excuse violations of a target's terms of service or a data source's acceptable use policy.
- Protect you from legal process, contractual liability, or professional discipline.

**If an action would be unlawful without Tor, it remains unlawful with Tor.**

### 5.3 Prohibited Tor uses

You must not use `--tor` to:

- Evade authorization requirements, access controls, rate limits, or bans imposed by a target or data source.
- Conceal unauthorized scanning, intrusion, harassment, or abuse.
- Circumvent sanctions, court orders, or lawful investigations.
- Access illegal content, marketplaces, or services.
- Interfere with critical infrastructure or cause denial of service.
- Evade monitoring that you are lawfully subject to, including employer or institutional policies.

### 5.4 Operational and legal realities

- **Tor is not anonymity.** Correlation, traffic analysis, exit-node observation, application errors, and operational mistakes can reveal your identity or your organization's involvement.
- **Exit nodes are public and untrusted.** Traffic may be monitored or modified by exit operators. Do not rely on Tor for confidentiality. AlOsint enforces TLS verification, but that is not a complete defense.
- **Some sources block Tor.** Public data sources and targets may refuse or challenge Tor traffic. AlOsint reports degradation but cannot guarantee access.
- **DNS behavior matters.** Depending on configuration, DNS resolution may occur outside the Tor circuit. AlOsint documents its behavior; you are responsible for understanding the leak surface.
- **Local law may restrict Tor.** Some jurisdictions regulate anonymity tools or require logging. You are responsible for compliance.
- **Your organization may prohibit Tor.** Using it on a corporate or institutional network may violate policy or law, independent of AlOsint.
- **Abuse complaints are traceable to you.** You are solely responsible for traffic originating from your systems and for any complaints, investigations, or penalties that follow.

### 5.5 No promise of evasion

AlOsint is not designed, marketed, or intended for evading attribution, law enforcement, or security controls. Any statement to the contrary is unauthorized and false.

---

## 6. Prohibition on Harvesting Leaked or Illicit Data

### 6.1 Absolute prohibition

**AlOsint must never be used to collect, aggregate, purchase, trade, or analyze leaked, breached, stolen, or otherwise illicitly obtained data.** This prohibition is permanent. It is not a V1.0 limitation and will not be relaxed in V2.0 or any later version.

This includes, without limitation:

- Breach dumps, database leaks, and credential dumps.
- Stealer logs, infostealer output, and malware-collected data.
- Combolists and credential-stuffing lists.
- Data from paste sites, leak forums, dark-web marketplaces, or closed criminal channels.
- Personal data obtained without a lawful basis or the data subject's consent where consent is required.
- Compromised credentials, session tokens, private keys, or authentication secrets.
- Financial data, government identifiers, health data, or other sensitive categories obtained unlawfully.
- Any data whose possession, processing, or distribution is itself unlawful.

### 6.2 No product pathway

AlOsint V1.0 contains no module, flag, plugin, configuration option, or data pathway for breach or leak data. The project will not add one. The absence is intentional and is a core design constraint, not an oversight.

### 6.3 If you encounter leaked data

If you inadvertently encounter leaked, breached, or otherwise illicit data while using AlOsint:

1. **Stop.** Do not download, copy, aggregate, index, or redistribute it.
2. **Do not use it.** Do not use it to access accounts, validate credentials, or enrich a profile.
3. **Record only what is necessary** to report the exposure.
4. **Notify the affected party or the appropriate authority** through a lawful, responsible channel.
5. **Seek legal advice** if you are unsure of your obligations.

Possession and processing of leaked personal data can itself be unlawful, even if you did not cause the leak.

### 6.4 No doxxing or aggregation of personal data

Do not use AlOsint, alone or with other tools, to build profiles of individuals, locate them, reveal their identity, or aggregate personal information for harassment, intimidation, or discrimination. Public availability does not equal ethical or lawful use.

---

## 7. Data Sources and Third-Party Terms

AlOsint queries third-party public sources, including certificate transparency logs, RDAP services, WHOIS servers, and geolocation and ASN providers. Your use of those sources is subject to their terms, acceptable use policies, and rate limits.

You must:

- Comply with each source's terms of service, robots directives, and rate limits.
- Not attempt to bypass quotas, authentication, or access restrictions.
- Not resell, redistribute, or republish third-party data in violation of its license.
- Provide attribution where required by a source's terms.
- Honor takedown, correction, and opt-out requests where applicable.
- Understand that data may be incomplete, outdated, or inaccurate, and that you are responsible for verifying it before relying on it.

AlOsint's rate limiter and backoff are courtesy controls. They do not transfer responsibility for compliance to the project.

---

## 8. Privacy and Data Protection

AlOsint output may contain personal data, including names, organizations, email addresses in registration records, IP addresses, and approximate locations. You are responsible for handling it lawfully.

Depending on your jurisdiction, you may need a lawful basis for processing, provide notices, honor data subject rights, minimize collection, limit retention, and secure the data. Relevant frameworks may include the GDPR, the UK GDPR, the CCPA/CPRA, and equivalent national and state laws.

You must:

- **Minimize.** Collect only what is necessary for your stated purpose.
- **Limit purpose.** Do not repurpose data for unrelated uses.
- **Limit retention.** Delete data when it is no longer needed, and do not build indefinite profiles.
- **Secure.** Protect reports and raw data from unauthorized access.
- **Respect rights.** Respond to access, correction, and deletion requests as required.
- **Avoid sensitive data.** Do not collect special categories of personal data unless you have a clear lawful basis and safeguards.
- **Avoid automated decisions.** Do not use AlOsint output as the sole basis for decisions that significantly affect individuals.

Geolocation is approximate and must never be presented as a person's precise location.

---

## 9. Disclosure and Responsible Reporting

If AlOsint helps you discover a security issue, misconfiguration, or exposure:

- Report it privately to the affected party through a responsible disclosure channel.
- Do not exploit it, publish it, or sell it.
- Do not access data beyond what is necessary to demonstrate the issue.
- Follow the affected party's disclosure policy and applicable law.
- Allow a reasonable remediation period before any publication.

Do not publish reports containing personal data, credentials, or sensitive infrastructure details. Redact before sharing.

---

## 10. Sanctions, Export, and Restricted Parties

You may not use or redistribute AlOsint if you are located in, ordinarily resident in, or acting on behalf of a sanctioned country or region, or if you are identified on a restricted-party list, to the extent such restrictions apply to this software under applicable law.

You are responsible for complying with export control and sanctions laws in your jurisdiction. The project makes no representation that the software is permitted in every country.

---

## 11. Security and Confidentiality

- Do not include secrets, credentials, or personal data in bug reports, issues, or pull requests.
- V2.0 API keys must be stored in environment variables or an OS keychain, never in reports or logs.
- AlOsint V1.0 does not transmit telemetry. If this ever changes, it will be opt-in, documented, and disclosed before collection.
- You are responsible for securing your own environment, including the Tor client, proxy configuration, shell history, and output files.

---

## 12. Disclaimer of Warranty

**ALOSINT IS PROVIDED "AS IS" AND "AS AVAILABLE," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE, AND NON-INFRINGEMENT.**

The project does not warrant that:

- Output is accurate, complete, current, or fit for any particular purpose.
- Data sources will remain available or continue to permit access.
- The software is free of defects or security vulnerabilities.
- Use of the software complies with the laws or terms applicable to you.

You are solely responsible for verifying results and for obtaining legal advice before relying on them.

---

## 13. Limitation of Liability

**TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE AUTHORS, CONTRIBUTORS, MAINTAINERS, AND COPYRIGHT HOLDERS OF ALOSINT SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES, INCLUDING BUT NOT LIMITED TO LOSS OF PROFITS, DATA, GOODWILL, OR BUSINESS OPPORTUNITY, ARISING OUT OF OR IN CONNECTION WITH THE USE OR INABILITY TO USE THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.**

This includes liability arising from:

- Unauthorized or unlawful use by any person.
- Reliance on inaccurate, incomplete, or outdated output.
- Actions taken by third parties, targets, data sources, or authorities.
- Network failures, rate limiting, blocking, or data source changes.
- Use of Tor or any other transport.
- Loss or exposure of data resulting from your configuration or environment.

Some jurisdictions do not allow the exclusion of certain warranties or the limitation of certain liabilities. In those jurisdictions, the exclusions and limitations apply to the fullest extent permitted by law.

---

## 14. Indemnity

To the maximum extent permitted by law, you agree to indemnify, defend, and hold harmless the authors, contributors, maintainers, and copyright holders of AlOsint from and against any claims, liabilities, damages, losses, and expenses, including reasonable legal fees, arising out of or in any way connected with:

- Your use of AlOsint.
- Your violation of this document.
- Your violation of any law, regulation, contract, or third-party right.
- Any unauthorized scan, collection, or disclosure you perform.
- Any claim by a third party relating to data you collected or processed.

---

## 15. Changes to This Document

This document may be updated as the project evolves and as legal review concludes. Material changes will be recorded in the repository history and noted in release notes. Continued use after a change constitutes acceptance of the updated document. If you do not agree to an update, stop using the software.

---

## 16. Severability and Governing Terms

If any provision of this document is held unenforceable, the remaining provisions remain in full force and effect, and the unenforceable provision will be interpreted to give maximum effect to its intent.

This document is not a license. The software license governs copying, modification, and distribution. In the event of a conflict between this document and the software license regarding acceptable use, the stricter provision applies to your use.

Nothing in this document limits rights that cannot be limited under applicable law, including mandatory consumer protections.

---

## 17. Acknowledgment

By using AlOsint, you acknowledge that:

1. You have read and understood this document.
2. You will use AlOsint only with authorization and only for lawful purposes.
3. You will not scan, enumerate, or probe any system without permission.
4. You understand that Tor is a transport option, not an anonymity guarantee or a legal shield.
5. You will not collect, aggregate, or use leaked, breached, or illicitly obtained data.
6. You are solely responsible for your use of the software and for compliance with applicable law.
7. The authors and maintainers disclaim liability to the maximum extent permitted by law.

**If you cannot accept these terms, do not use AlOsint.**

---

## 18. Reporting Misuse and Contact

To report misuse of AlOsint, a security vulnerability in the software, or a concern about this document, contact the maintainers through the repository's published security contact. Do not include personal data, credentials, or leaked data in your report.

For legal questions about your own use, consult a qualified lawyer in your jurisdiction. The maintainers cannot provide legal advice.

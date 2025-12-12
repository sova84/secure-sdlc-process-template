---
weight: 10
title: Secure Application Design Checklist
---


# Secure Application Design Checklist

## What is the Secure Application Design Checklist?

The **Secure Application Design Checklist** is a list of requirements and suggestions that a product manager, architect, or other development personnel can run through to make sure they've fully covered all security requirements during their SDLC process.

The checklist is based on the list of security requirements outlined in the [Security Requirements](./Security-Requirements.md) document.

## Checklist

### Authentication and Authorization

#### Web Pages & APIs

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Ensure all API endpoints that serve non-public data utilize BC tokens/Bifrost for authentication and authorization for requests | Requirement | [API Best Practices - Access Controls](../Coding%20Practice/API-Best-Practices.md#access-controls) / [Cross-Site Request Forgery](../Coding%20Practice/Preventing-Common-Web-Attacks.md#preventing-cross-site-request-forgery) |
| If RBAC is being implemented, ensure endpoints are only accessible by the roles that require it | Requirement | [API Best Practices - Access Controls](../Coding%20Practice/API-Best-Practices.md#access-controls) |
| Authentication tokens must have a static expiration date that's enforced on the backend network | Requirement | [API Best Practices - Replay Attacks](../Coding%20Practice/API-Best-Practices.md#replay-attacks) / [AuthZ and AuthN Guidelines - Limited Token Lifetimes](../Coding%20Practice/AuthZ-AuthN-Guidelines.md#limited-token-lifetimes) |
| Ensure sensitive API actions can't be performed via click-jacking | Requirement | [Click-Jacking](../Coding%20Practice/Preventing-Common-Web-Attacks.md#preventing-clickjacking) |
| If redirect URIs are being used with OAuth2 authentication requests, ensure the URIs are validated as pointing to the expected FQDN | Requirement | [AuthZ and AuthN Guidelines - Validating OAuth2 Redirect URIs](../Coding%20Practice/AuthZ-AuthN-Guidelines.md#validating-oauth2-redirect-uris) |
| Limit OAuth2 scopes in line with the Principle of Least Privilege | Requirement | [AuthZ and AuthN Guidelines - Limit OAuth2 Scope](../Coding%20Practice/AuthZ-AuthN-Guidelines.md#limit-oauth2-scope-by-the-principle-of-least-privilege) |
| Use and validate the `state` parameter when validating OAuth2 authentication requests | Requirement | [AuthZ and AuthN Guidelines - Validating the OAuth2 State Parameter](../Coding%20Practice/AuthZ-AuthN-Guidelines.md#validating-the-oauth2-state-parameter) |

#### User Management

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| If passwords are being used, ensure the password policy complies with NIST 800-63 guidelines | Requirement | [AuthZ and AuthN Guidelines - Auth Guidelines](../Coding%20Practice/AuthZ-AuthN-Guidelines.md#authentication-guidelines) |
| Disable/delete user account records after a specified amount of inactivity | Recommendation | [Data Retention](../Coding%20Practice/Data-Retention.md) |
| Support SSO authentication for users (e.g. Okta, Google, Auth0) | Recommendation | N/A |
| Allow local accounts to be configured for use with Multi-Factor Authentication | Required for sensitive applications | [AuthZ and AuthN Guidelines - Require MFA](../Coding%20Practice/AuthZ-AuthN-Guidelines.md#require-multi-factor-authentication-for-sensitive-applications) |

#### Network-Accessible Applications

**Ex:** an encoding application listening on port 12345 for encoding requests and serving up completed encoding jobs

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Ensure all incoming network requests for non-public data or sensitive actions are authenticated and authorized before being processed | Requirement | N/A |
| Configure network access such that only the IP addresses/network hosts that need access to it, have access to it, and only for the ports and protocols in use (e.g. configure Security Groups to only allow web traffic from TESCO IP addresses for internal applications) | Requirement | N/A |

### Input Validation/Output Encoding

#### Web Pages & APIs

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Ensure any untrusted input is properly sanitized/encoded upon output | Requirement | [XSS Attacks](../Coding%20Practice/Preventing-Common-Web-Attacks.md#preventing-xss) |
| Add checks and restrictions within web APIs to account for untrusted input sent to it | Requirement | [API Best Practices - Input Validation](../Coding%20Practice/API-Best-Practices.md#input-validation) |
| Set the Content-Security Policy to the proper values to restrict what resources can be loaded | Requirement | [HTTP Headers - CSP](../Coding%20Practice/HTTP-Header-Security.md#content-security-policy-csp) |
| Database calls must use paramaterized queries, where applicable | Requirement | [SQL Injection](../Coding%20Practice/Preventing-Common-Web-Attacks.md#preventing-sql-injection) |
| Any service that accepts network addresses (FQDNs, IP addresses, hostnames) with the intention of initiating a connection to that address should ensure proper validation is in place to prevent malicious addresses from being used | Requirement | [Server-Side Request Forgery](../Coding%20Practice/Preventing-Common-Web-Attacks.md#server-side-request-forgery-ssrf) |
| Arbitrary file uploads must be properly validated upon upload | Requirement | [Arbitrary File Uploads](../Coding%20Practice/Preventing-Common-Web-Attacks.md#arbitrary-file-uploads) |
| Applications that use untrusted input for site redirection (HTTP 30x) destinations must protect against open-redirects | Requirement | [Open Redirect] |
| Prevent content-sniffing by browsers | Requirement | [HTTP Headers - X-Content-Type-Options](../Coding%20Practice/HTTP-Header-Security.md#notes-on-apis) |
| Take into account the possibility of HTTP smuggling attacks when forwarding HTTP requests through multiple services | Requirement | [HTTP Request Smuggling](../Coding%20Practice/Preventing-Common-Web-Attacks.md#http-request-smuggling-aka-http-desync-attacks) |
| Implement request integrity | Recommendation | [API Best Practices - Request Integrity](../Coding%20Practice/API-Best-Practices.md#request-integrity) |

#### Networked Applications

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Prefer using memory-safe languages when creating services and applications | Requirement | N/A |
| When using memory-unsafe languages, ensure untrusted intput isn't used for declaring buffer size, and that buffer size is appropriate for the incoming data the buffer set to hold | Requirement | N/A |
| Refrain from using object deserialization with untrusted data | Recommendation | N/A |

### Secrets Management

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Ensure no plaintext secrets (passwords, API tokens, etc) are included within any code | Requirement | [Credential Leaks](../Coding%20Practice/Preventing-Common-Web-Attacks.md#credential-leaks) |
| Any credentials needed for the application should be independently generated for the application, where applicable | Requirement | N/A |
| Secrets that needed to be statically stored for application deployment must use secure storage methods in accordance with [TESCO cryptogaphic standards] | Requirement | [Credential Leaks](../Coding%20Practice/Preventing-Common-Web-Attacks.md#credential-leaks) |
| For web applications, make sure the Referrer-Policy header is set to prevent unnecessary data leakage | Requirement | [HTTP Headers - Referrer-Policy](../Coding%20Practice/HTTP-Header-Security.md#referrer-policy) |

### Encryption

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Confirm application confirms to TESCO Cryptography Standards | Requirement | [BC Internal - SSDLC - Cryptography Standards] |

#### Web Pages & APIs

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Ensure TLS is used for all network communications, both internal and external | Requirement | [BC Internal - Guide to TLS - Should I Use TLS?] |
| When configuring TLS, ensure secure ciphers are used | Requirement | [BC Internal - Guide to TLS - Protocol and Ciphers] |
| Use HTTP Strict-Transport Security (HSTS) for all HTTP requests | Requirement | [HTTP Headers - HTTP Strict Transport Security](../Coding%20Practice/HTTP-Header-Security.md#http-strict-transport-security) |
| When generating a TLS certificate for a service, make sure to include ALL FQDNs that point to that service as `Common Name` values | Requirement | [HTTP Headers - HTTP Strict Transport Security](../Coding%20Practice/HTTP-Header-Security.md#http-strict-transport-security) |
| Make sure HTTP redirects (HTTP 30x) do not redirect users through HTTP (i.e. non-TLS, non-encrypted) endpoints before directing them to a TLS endpoint | Requirement | N/A |

#### User Management

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Ensure passwords are hashed, not encrypted | Requirement | [BC Internal - SSDLC - Cryptography - Storing Passwords] |
| Passwords must be salted when stored, before being hashed | Requirement | [BC Internal - SSDLC - Cryptography - Salting Passwords] |
| Make sure a TESCO-approved password hashing algorithm is used for storing passwords | Requirement | [BC Internal - SSDLC - Cryptography - Storing Passwords - Algorithms] |
| Make sure a TESCO-approved CSPRNG is used for generating password salts | Requirement | [BC Internal - SSDLC - Cryptography - Storing Passwords - Salting Procedures] |

#### Persistent Data Encryption

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Confirm all data is encrypted-at-rest at the disk level when stored persistently | Requirement | [BC Internal - SSDLC - Cryptography - Encryption-at-Rest] |
| Confirm confidential data (e.g. a customer's API token to a third-party service) is actively encrypted before being stored within a database | Requirement | [BC Internal - SSDLC - Cryptography - Encryption-at-Rest] |

#### Software Integrity Validation

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Confirm all code has been peer-reviewed before deployment | Requirement | [AWS Well-Architected Framework - Security Pillar - SEC11-BP04 Conduct code reviews](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) |
| Ensure all artifacts are cryptographically signed with a valid certificate | Recommendation | [BC Internal - SSDLC - Cryptography - Digital Signatures] |

### Infrastructure

#### Cloud Security

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Ensure TESCO Cloud Security Standards are met when creating or updating any cloud infrastructure | Requirement | [BC Internal - Cloud Security Standards] |
| Cloud resources must be configured following the Principle of Least Privilege | Requirement | [BC Internal - Guide to Security in AWS] |
| Utilize a dedicated AWS account for a net-new service, i.e. don't mix resources from multiple resources into a single account | Requirement | [AWS Well-Architected Framework - Security Pillar - SEC01-BP01 Separate workloads using accounts] |
| Infrastructure-as-Code must be used for management of resources | Requirement | [AWS Well-Architected Framework - Security Pillar - SEC01-BP06 Automate deployment of standard security controls](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) |
| Infrastructure-as-Code must be deployed using CI/CD, preferably Jenkins/Spinnaker | Requirement | [AWS Well-Architected Framework - Security Pillar - SEC06-BP04 Validate software integrity](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) |
| Ensure a high-level architectural diagram is created for the service and available to the SecEng and Ops teams | Requirement | [AWS Well-Architected Framework - Security Pillar - SEC01-BP07 Identify threats and prioritize mitigations using a threat model](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) |

#### Networking

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Resources must be properly segmented at the network level, e.g. the web server and the API for your service should likely not be in the same VPC/subnet | Requirement | [AWS Well-Architected Framework - Security Pillar - SEC05-BP01 Create network layers](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) |
| Only allow the minimal amount of network access required when creating security groups | Requirement | [AWS Well-Architected Framework - Security Pillar - SEC05-BP02 Control traffic flow within your network layers](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) |
| Public access is only granted to services, networks, and ports that require public access by design | Requirement | [AWS Well-Architected Framework - Security Pillar - SEC05-BP02 Control traffic flow within your network layers](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) |

#### Container Security

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Make sure to only use official, up-to-date official images | Requirement | [BC Internal - Docker Security Guide] |
| Run applications as service account users as opposed to the default `root` user | Requirement | [BC Internal - Docker Security Guide] |
| Only use `EXPOSE` with ports that are in use and need to be exposed outside of the container | Requirement | [BC Internal - Docker Security Guide] |
| Do not include any secrets or sensitive data within a container | Requirement | [BC Internal - Docker Security Guide] |
| Any static secrets in use by the container during runtime must be encrypted when used within the Kubernetes manifest in accordance with TESCO cryptographic standards | Requirement | [BC Internal - SSDLC - Container Security] |
| Review the TESCO Docker Security Guide to ensure your container image is as secure as possible | Recommendation | [BC Internal - Docker Security Guide] |

#### Kubernetes Security

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Run the container as non-root | Required | [BC Internal - Kubernetes Security Guide] |
| Disallow container privilege escalation | Required | [BC Internal - Kubernetes Security Guide] |
| Do not run the container in privileged mode | Required | [BC Internal - Kubernetes Security Guide] |
| Implement a Seccomp policy | Recommendation | [BC Internal - Kubernetes Security Guide] |
| Implement kernel security defenses | Recommendation | [BC Internal - Kubernetes Security Guide] |
| Review the TESCO Kubernetes Security Guide to ensure your container image is deployed as securely as possible | Recommendation | [BC Internal - Kubernetes Security Guide] |

### Logging

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Configure log forwarding to a remote log server, SaaS service, or SIEM | Requirement | [BC Internal - SSDLC - Logging] |
| For public applications, logs must be traceable to an IP and user/customer | Requirement | N/A |
| Ensure that confidential data values are excluded or scrubbed before being written to logs | Requirement | N/A |
| Ensure logs are retained for at least 30 days | Requirement | N/A |
| Include the ability for verbose logging to log any untrusted data and associated remote identifiers (e.g. user ID) | Recommendation | N/A |

### Data Retention

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Ensure all PII-related data points that are collected and persistently stored include a method for automated or on-demand removal | Requirement | [Data Retention] |
| Make sure to set a static expiration date for all data points of a given set | Requirement | [Data Retention] |
| Expiration dates set for data points must be set only as long as the data's usable lifespan to the business | Requirement |

### Security Tools

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Configure source code to be scanned by SAST platform | Requirement | [BC Internal - Tools - SAST] |
| Integrate source code with dependency management application | Requirement | [BC Internal - Tools - Dependency Management] |

### Vulnerability Scanning/Patch Management

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Ensure application containers are being scanned by vulnerability management platform | Requirement | [BC Internal - Tools - Vulnerability Scanning/Management]
| Confirm application containers are patched for all critical and high vulnerabilities that have a fix available, before being deployed to production environments | Requirement  |
| Ensure that patching standards are followed and a plan is in place to patch the application and its infrastructure on a regular basis | Requirement |

### SCM Security

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Ensure source code organizations and repos are only accessible by users who truly require access | Required | N/A |
| Refrain from checking in any secret or confidential data to source code repos | Requirement | 
| Don't create repos in personal organizations. If this _is_ needed, ensure that it is set to `private` visibility upon creation | Requirement | [Github Docs - Repo Visibility](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility) |
| Require at least two reviews for PRs to be merged | Recommendation | [Github Docs - PR Review Requirements](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches#require-pull-request-reviews-before-merging) |
| Implement branch protections on production and main branches | Recommendation | [Github Docs - Protected Branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/defining-the-mergeability-of-pull-requests/about-protected-branches) |

### CI/CD Security

| Action | Requirement or Recommendation? | TESCO Reference |
| ------ | ------------------------------ | ------------------ |
| Only use CI/CD platforms approved for use by TESCO | Required | N/A |
| Refrain from using hard-code secrets for deployments | Required | [BC Internal - SSDLC - Using Application Secrets Securely] |
| Have a plan in place to regularly reassess the CI/CD pipeline's security | Required | [AWS Well-Architected Framework - Security Pillar - SEC11-BP07 Regularly assess security properties of the pipelines](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html) |

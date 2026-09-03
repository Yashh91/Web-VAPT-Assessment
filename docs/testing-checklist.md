# Web Application VAPT Testing Checklist

## 1. Information Gathering

- [ ] Identify application entry points
- [ ] Identify technologies
- [ ] Identify web server
- [ ] Identify application framework
- [ ] Discover endpoints
- [ ] Identify parameters
- [ ] Review HTTP headers
- [ ] Review cookies
- [ ] Map application functionality

## 2. Authentication Testing

- [ ] Login functionality
- [ ] Authentication bypass
- [ ] Weak password policy
- [ ] Account enumeration
- [ ] Password reset functionality
- [ ] Logout functionality
- [ ] Authentication error handling
- [ ] Session timeout

## 3. Authorization Testing

- [ ] Horizontal privilege escalation
- [ ] Vertical privilege escalation
- [ ] IDOR
- [ ] BOLA
- [ ] Access control bypass
- [ ] Unauthorized endpoint access

## 4. Session Management

- [ ] Session cookie security
- [ ] Secure flag
- [ ] HttpOnly flag
- [ ] SameSite attribute
- [ ] Session expiration
- [ ] Session fixation
- [ ] Session invalidation after logout

## 5. Input Validation

- [ ] SQL Injection
- [ ] Cross-Site Scripting
- [ ] Command Injection
- [ ] Parameter tampering
- [ ] Malicious input handling
- [ ] Server-side validation

## 6. CSRF

- [ ] Identify state-changing requests
- [ ] Check CSRF tokens
- [ ] Test token validation
- [ ] Check SameSite cookie configuration

## 7. File Upload

- [ ] File type validation
- [ ] Extension validation
- [ ] MIME type validation
- [ ] File size restrictions
- [ ] Filename handling
- [ ] Uploaded file access controls

## 8. Security Configuration

- [ ] Security headers
- [ ] HTTPS configuration
- [ ] Information disclosure
- [ ] Debug mode
- [ ] Directory listing
- [ ] Backup files
- [ ] Error messages
- [ ] Unnecessary services

## 9. Business Logic

- [ ] Parameter manipulation
- [ ] Workflow bypass
- [ ] Missing validation
- [ ] Price/quantity manipulation
- [ ] Unauthorized workflow access
- [ ] Request sequence manipulation

## 10. Client-Side Security

- [ ] DOM-based XSS
- [ ] Client-side validation bypass
- [ ] Sensitive data in JavaScript
- [ ] Exposed API keys
- [ ] Insecure client-side storage

## 11. API Testing

- [ ] API endpoint discovery
- [ ] Authentication
- [ ] Authorization
- [ ] IDOR/BOLA
- [ ] Parameter tampering
- [ ] HTTP method testing
- [ ] Rate limiting
- [ ] Excessive data exposure

## 12. Validation

- [ ] Reproduce vulnerability
- [ ] Verify impact
- [ ] Collect evidence
- [ ] Remove false positives
- [ ] Assign severity
- [ ] Map to OWASP

## 13. Reporting

- [ ] Vulnerability title
- [ ] Description
- [ ] Affected endpoint
- [ ] Evidence
- [ ] Impact
- [ ] CVSS
- [ ] OWASP mapping
- [ ] Remediation
- [ ] Retest status

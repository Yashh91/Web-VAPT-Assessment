# Assessment Scope

## Purpose

This document defines the scope and boundaries of the Web Application VAPT assessment.

## Target

Target Application:

`http://localhost:3000`

The default target is an intentionally vulnerable application running in a controlled local testing environment.

## Testing Type

- Web Application VAPT
- Black-box testing
- Manual security testing
- Automated security testing
- Vulnerability validation
- Retesting

## In-Scope

The following areas may be assessed:

- Web application pages
- Authentication
- Authorization
- Sessions
- APIs
- Input parameters
- File upload functionality
- Application configuration
- Business logic
- Client-side functionality

## Out-of-Scope

The following are excluded unless explicitly authorized:

- Third-party applications
- Production systems
- External infrastructure
- Denial-of-Service testing
- Social engineering
- Physical security
- Real user accounts
- Systems not owned or authorized by the tester

## Testing Environment

Recommended environments:

- OWASP Juice Shop
- DVWA
- WebGoat
- Locally developed vulnerable applications

## Authorization

Testing must only be performed against systems where the tester has explicit permission.

This project is intended for educational purposes and authorized security assessments only.

## Evidence Handling

Testing evidence may include:

- HTTP requests
- HTTP responses
- Screenshots
- Vulnerability details
- Test results

Sensitive information should not be committed to the repository.

## Responsible Testing

Testing should minimize disruption to the target application and avoid unnecessary access to sensitive information.

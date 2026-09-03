# Project Architecture

## Overview

The Web VAPT Assessment project provides a structured workflow for assessing web application security.

The system combines automated testing, manual validation, risk assessment, reporting, and optional AI-assisted analysis.

## Architecture

```text
                    Target Web Application
                              |
                              v
                    +-------------------+
                    |       Recon       |
                    +---------+---------+
                              |
              +---------------+---------------+
              |               |               |
              v               v               v
            Nmap          Endpoint        Technology
                           Discovery       Detection
              |               |               |
              +---------------+---------------+
                              |
                              v
                    +-------------------+
                    | Vulnerability     |
                    | Testing           |
                    +---------+---------+
                              |
       +----------+-----------+-----------+----------+
       |          |           |           |          |
       v          v           v           v          v
     SQLi       XSS         IDOR       CSRF       Auth
       |          |           |           |          |
       +----------+-----------+-----------+----------+
                              |
                              v
                    +-------------------+
                    | Vulnerability     |
                    | Validation        |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Evidence          |
                    | Collection        |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Risk Assessment   |
                    | CVSS + OWASP      |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | AI-Assisted       |
                    | Analysis          |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Remediation       |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | Retesting         |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    | VAPT Report       |
                    +-------------------+

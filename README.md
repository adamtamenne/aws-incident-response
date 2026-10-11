# AWS Incident Response Scripts

Automated scripts for AWS security incident response. Each directory is a self-contained script with its own README.

## Scripts

| Script | Description |
|--------|-------------|
| [EC2 Forensic Isolation](ec2-forensic-isolation/) | Isolates a compromised EC2 instance — tags, snapshots EBS, detaches IAM role, locks down security groups, enables termination protection |
| [IAM Identity Containment](iam-containment/) | Quarantines a compromised IAM user or role — deactivates keys, revokes console and sessions, attaches deny-all policies, detaches instance profiles |

## Repository Structure

```
aws-incident-response-scripts/
├── ec2-forensic-isolation/
│   ├── isolate-instance.sh
│   └── README.md
├── iam-containment/
│   ├── quarantine-iam-identity.sh
│   └── README.md
└── README.md
```

## Prerequisites

- AWS CLI configured with appropriate credentials
- Bash 4+

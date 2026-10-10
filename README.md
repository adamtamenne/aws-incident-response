# AWS Incident Response Scripts

Automated scripts for AWS security incident response. Each directory is a self-contained script with its own README.

## Scripts

| Script | Description |
|--------|-------------|
| [EC2 Forensic Isolation](ec2-forensic-isolation/) | Isolates a compromised EC2 instance — tags, snapshots EBS, detaches IAM role, locks down security groups, enables termination protection |

## Repository Structure

aws-incident-response-scripts/
├── ec2-forensic-isolation/
│ ├── isolate-instance.sh
│ └── README.md
└── README.md


## Prerequisites

- AWS CLI configured with appropriate credentials
- Bash 4+

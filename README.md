# AWS Incident Response

Scripts and playbooks for AWS security incident response.

Each directory is a self-contained runbook: a script that automates the response, a write-up explaining what it does and why, and the AWS services involved.

## Runbooks

| Runbook | Description |
|---------|-------------|
| [EC2 Forensic Isolation](ec2-forensic-isolation/) | Isolate a compromised EC2 instance: snapshot volumes, swap to a forensic-only security group, block egress, enable termination protection |

## Prerequisites

- AWS CLI configured with appropriate credentials
- Bash 4+
- `curl` (for auto-detecting public IP)

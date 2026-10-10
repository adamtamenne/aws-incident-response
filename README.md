# EC2 Forensic Isolation

This script isolates a compromised EC2 instance for forensic investigation. Given an instance ID, it tags the instance, detaches its IAM role, snapshots all EBS volumes, swaps its security groups to allow only SSH from your IP with no egress, enables termination protection, and outputs a JSON forensic report.

## Usage

```bash
./isolate-instance.sh <instance-id> [--forensic-ip <your-ip>]

## Runbooks

| Runbook | Description |
|---------|-------------|
| [EC2 Forensic Isolation](ec2-forensic-isolation/) | Isolate a compromised EC2 instance: snapshot volumes, swap to a forensic-only security group, block egress, enable termination protection |

## Prerequisites

- AWS CLI configured with appropriate credentials
- Bash 4+
- `curl` (for auto-detecting public IP)

# AWS CloudTrail IR Guide Part 2 — DaC gap review

Source: https://aws.amazon.com/blogs/security/incident-response-guide-for-aws-cloudtrail-investigations-part-2/

## Scenario 3 chain
SSRF → IMDSv1 (`ec2RoleDelivery=1.0`) → IAM CreateUser AccessDenied (adm1n) → ConsoleLogin MFAUsed=No → Region hop → Bedrock ListFoundationModels → Converse

## New rules DAC-AWS-0050…0059
See detections on branch feat/aws-cloudtrail-ir-part2. Field validation against blog payloads: PASS.

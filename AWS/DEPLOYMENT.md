# Nmap MCP Server - ECS Deployment Guide

## Prerequisites

1. AWS CLI configured with appropriate credentials
2. Docker installed locally
3. AWS account with permissions for ECS, ECR, VPC, IAM, and CloudFormation

## Deployment Steps

### 1. Build and Push Docker Image

```bash
# Get your AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
AWS_REGION="us-east-1"  # Change to your preferred region
CUSTOMER_NAME="nmap-mcp"
ENV_NAME="dev"

# Create ECR repository (if not exists)
aws ecr create-repository --repository-name ${CUSTOMER_NAME}-${ENV_NAME} --region ${AWS_REGION} || true

# Login to ECR
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Build the Docker image
docker build -t ${CUSTOMER_NAME}-${ENV_NAME}:latest .

# Tag the image
docker tag ${CUSTOMER_NAME}-${ENV_NAME}:latest ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${CUSTOMER_NAME}-${ENV_NAME}:latest

# Push to ECR
docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${CUSTOMER_NAME}-${ENV_NAME}:latest
```

### 2. Deploy CloudFormation Stack

```bash
# Deploy the stack
aws cloudformation create-stack \
  --stack-name ${CUSTOMER_NAME}-${ENV_NAME} \
  --template-body file://AWS/ECS.yml \
  --parameters \
    ParameterKey=CustomerName,ParameterValue=${CUSTOMER_NAME} \
    ParameterKey=EnvironmentName,ParameterValue=${ENV_NAME} \
    ParameterKey=ImageTag,ParameterValue=latest \
    ParameterKey=DesiredTaskCount,ParameterValue=1 \
    ParameterKey=InstanceType,ParameterValue=t3a.medium \
  --capabilities CAPABILITY_IAM \
  --region ${AWS_REGION}

# Monitor stack creation
aws cloudformation wait stack-create-complete \
  --stack-name ${CUSTOMER_NAME}-${ENV_NAME} \
  --region ${AWS_REGION}

# Get the load balancer URL
aws cloudformation describe-stacks \
  --stack-name ${CUSTOMER_NAME}-${ENV_NAME} \
  --query 'Stacks[0].Outputs[?OutputKey==`LoadBalancerURL`].OutputValue' \
  --output text \
  --region ${AWS_REGION}
```

### 3. Update Existing Stack

```bash
# Update the stack with new image
aws cloudformation update-stack \
  --stack-name ${CUSTOMER_NAME}-${ENV_NAME} \
  --template-body file://AWS/ECS.yml \
  --parameters \
    ParameterKey=CustomerName,UsePreviousValue=true \
    ParameterKey=EnvironmentName,UsePreviousValue=true \
    ParameterKey=ImageTag,ParameterValue=latest \
  --capabilities CAPABILITY_IAM \
  --region ${AWS_REGION}
```

## Configuration Parameters

- **CustomerName**: Project identifier (default: nmap-mcp)
- **EnvironmentName**: Environment (dev/staging/prod)
- **ImageTag**: Docker image tag (default: latest)
- **InstanceType**: EC2 instance type (default: t3a.medium)
- **DesiredCapacity**: Number of EC2 instances (default: 1)
- **DesiredTaskCount**: Number of ECS tasks (default: 1)
- **CertificateArn**: ACM certificate ARN for HTTPS (optional)

## Architecture

- VPC with public and private subnets across 2 AZs
- Application Load Balancer in public subnets
- ECS cluster with EC2 instances in private subnets
- NAT Gateways for outbound internet access
- ECR repository for Docker images
- CloudWatch Logs for container logs

## Accessing the Service

After deployment, access your nmap MCP server at:
```
http://<LoadBalancerDNS>/mcp
```

## Cleanup

```bash
# Delete the stack
aws cloudformation delete-stack \
  --stack-name ${CUSTOMER_NAME}-${ENV_NAME} \
  --region ${AWS_REGION}

# Delete ECR images (optional)
aws ecr batch-delete-image \
  --repository-name ${CUSTOMER_NAME}-${ENV_NAME} \
  --image-ids imageTag=latest \
  --region ${AWS_REGION}
```

## Troubleshooting

### Check ECS Service Status
```bash
aws ecs describe-services \
  --cluster ${CUSTOMER_NAME}-${ENV_NAME} \
  --services ${CUSTOMER_NAME}-${ENV_NAME} \
  --region ${AWS_REGION}
```

### View Container Logs
```bash
aws logs tail /ecs/${CUSTOMER_NAME}-${ENV_NAME} --follow --region ${AWS_REGION}
```

### Check Task Status
```bash
aws ecs list-tasks \
  --cluster ${CUSTOMER_NAME}-${ENV_NAME} \
  --region ${AWS_REGION}
```

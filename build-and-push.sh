#!/bin/bash
set -e

# Configuration
CUSTOMER_NAME="${CUSTOMER_NAME:-nmap-mcp}"
ENV_NAME="${ENV_NAME:-dev}"
AWS_REGION="${AWS_REGION:-us-east-1}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

# Get AWS Account ID
echo "Getting AWS Account ID..."
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

if [ -z "$AWS_ACCOUNT_ID" ]; then
    echo "Error: Could not get AWS Account ID. Make sure AWS CLI is configured."
    exit 1
fi

echo "AWS Account ID: $AWS_ACCOUNT_ID"
echo "Region: $AWS_REGION"
echo "Repository: ${CUSTOMER_NAME}-${ENV_NAME}"
echo "Image Tag: $IMAGE_TAG"

# ECR Repository URI
ECR_REPO="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${CUSTOMER_NAME}-${ENV_NAME}"

# Login to ECR
echo ""
echo "Logging in to ECR..."
aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com

# Build the Docker image for AMD64 (ECS uses x86_64 instances)
echo ""
echo "Building Docker image for linux/amd64..."
docker build --platform linux/amd64 -t ${CUSTOMER_NAME}-${ENV_NAME}:${IMAGE_TAG} .

# Tag the image for ECR
echo ""
echo "Tagging image for ECR..."
docker tag ${CUSTOMER_NAME}-${ENV_NAME}:${IMAGE_TAG} ${ECR_REPO}:${IMAGE_TAG}

# Push to ECR
echo ""
echo "Pushing image to ECR..."
docker push ${ECR_REPO}:${IMAGE_TAG}

echo ""
echo "✅ Successfully pushed image to ECR!"
echo "Image URI: ${ECR_REPO}:${IMAGE_TAG}"

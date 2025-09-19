# Deploy-Setup

A comprehensive deployment setup tool for After Dark Systems that automates infrastructure provisioning and application deployment across various cloud providers.

## Overview

Deploy-Setup streamlines the process of setting up cloud infrastructure and deployment configurations for web applications. It generates Infrastructure as Code (Terraform), configuration management (Ansible), and deployment scripts tailored to your project type and requirements.

## Features

- 🚀 **Automated Infrastructure Setup**: Generate complete Terraform configurations for AWS, GCP, and Azure
- 🔧 **Configuration Management**: Create Ansible playbooks for application deployment and server provisioning
- 🎯 **Project Type Detection**: Automatically detect Node.js, Python, PHP, or static website projects
- 🏗️ **Multiple Deployment Options**: Support for EC2, ECS, RDS, S3, and Load Balancers
- 🔒 **Security Features**: Built-in secrets tagging and permission checking
- 📚 **Complete Documentation**: Generate deployment guides and documentation
- 🤖 **Interactive & Non-Interactive Modes**: CLI wizard or command-line arguments

## Supported Project Types

- **Node.js** - Express, Next.js, and other Node.js applications
- **Python** - Flask, Django, FastAPI applications
- **PHP** - Laravel, WordPress, custom PHP applications
- **Static** - HTML/CSS/JS websites and SPAs

## Infrastructure Components

- **Compute**: EC2 instances, ECS containers
- **Database**: RDS (MySQL, PostgreSQL)
- **Storage**: S3 buckets
- **Networking**: VPC, Load Balancers (ALB/ELB)
- **Security**: Security groups, IAM roles

## Quick Start

### Installation

Clone the repository:
```bash
git clone https://github.com/straticus1/deploy-setup.git
cd deploy-setup
```

Make the script executable (if needed):
```bash
chmod +x bin/deploy-setup
```

### Basic Usage

**Interactive Setup:**
```bash
./bin/deploy-setup
```

**Command Line Setup:**
```bash
# Basic Node.js project with EC2
./bin/deploy-setup --project=./my-app --type=node --ec2

# Full setup with database and load balancer
./bin/deploy-setup --project=./my-app --type=python --ec2 --rds=postgres --elb --s3

# ECS deployment with multiple containers
./bin/deploy-setup --project=./my-app --type=node --ecs=3 --rds
```

## Command Line Options

```
--cloud=PROVIDER         Cloud provider (aws, gcp, azure) [default: aws]
--project=PATH          Path to project directory [required]
--type=TYPE             Project type (node, python, php, static)
--name=NAME             Project name (auto-detected if not provided)
--ec2                   Use EC2 instances
--ecs[=NUM]             Use ECS containers (default: 1 instance)
--rds[=TYPE]            Use RDS database (mysql, postgres)
--s3                    Include S3 bucket
--elb                   Include load balancer
--non-interactive       Run without prompts
--force-push            Push to git remote after setup
--tag-secrets           Tag secrets in project files
--check-permissions     Check file permissions
--help, -h              Show help message
--version, -v           Show version
```

## Generated Structure

After running deploy-setup, your project will have:

```
my-project/
├── terraform/              # Infrastructure as Code
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── ec2.tf              # If using EC2
│   ├── ecs.tf              # If using ECS
│   ├── rds.tf              # If using RDS
│   ├── s3.tf               # If using S3
│   └── elb.tf              # If using Load Balancer
├── ansible/                # Configuration Management
│   ├── site.yml
│   ├── inventory
│   ├── ansible.cfg
│   └── roles/
│       ├── common/
│       ├── security/
│       ├── nginx/
│       ├── [project-type]/
│       └── deploy/
├── scripts/                # Deployment Scripts
│   ├── deploy-terraform.sh
│   └── deploy-ansible.sh
├── docs/                   # Documentation
│   └── README.md
└── .project_status         # Project metadata
```

## Deployment Workflow

1. **Generate Configurations**
   ```bash
   ./bin/deploy-setup --project=./my-app --type=node --ec2 --rds
   ```

2. **Deploy Infrastructure**
   ```bash
   cd my-app
   ./scripts/deploy-terraform.sh
   ```

3. **Configure Servers** (update inventory first)
   ```bash
   vim ansible/inventory
   ./scripts/deploy-ansible.sh
   ```

## Examples

### Node.js Application with Database
```bash
./bin/deploy-setup \
  --project=./my-node-app \
  --type=node \
  --ec2 \
  --rds=mysql \
  --s3 \
  --elb
```

### Python Application with ECS
```bash
./bin/deploy-setup \
  --project=./my-python-app \
  --type=python \
  --ecs=2 \
  --rds=postgres \
  --s3
```

### Static Website
```bash
./bin/deploy-setup \
  --project=./my-website \
  --type=static \
  --s3 \
  --elb
```

## Utility Functions

The tool includes several utility functions for maintenance:

- **Tag Secrets**: `./bin/deploy-setup --project=./my-app --tag-secrets`
- **Check Permissions**: `./bin/deploy-setup --project=./my-app --check-permissions`

## Prerequisites

- **Terraform** (>= 1.0) - For infrastructure provisioning
- **Ansible** (>= 2.9) - For configuration management
- **Cloud Provider CLI** - AWS CLI, gcloud, or Azure CLI
- **Git** - For version control

## Configuration

Before deploying, ensure you have:

1. **Cloud Provider Credentials** configured (AWS CLI, gcloud, etc.)
2. **SSH Keys** set up for server access
3. **Domain Names** configured (if using load balancers)

## Contributing

This is a private tool for After Dark Systems. For issues or feature requests, please contact the development team.

## License

Private - After Dark Systems Internal Tool

## Support

For support and documentation, see the generated `docs/README.md` in your project directory after setup.

---

**Deploy-Setup v1.0.0** - Streamlining deployment automation for modern web applications.
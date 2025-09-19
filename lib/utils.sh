#!/usr/bin/env bash

# Utility functions for deploy-setup

# Logging functions
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

error_exit() {
    log "ERROR: $1" >&2
    exit 1
}

warn() {
    log "WARNING: $1" >&2
}

# Directory and file management
ensure_directory_exists() {
    local dir="$1"
    if [ ! -d "$dir" ]; then
        log "Creating directory: $dir"
        mkdir -p "$dir"
    else
        log "Directory exists: $dir"
    fi
}

# Project status management
update_project_status() {
    local key="$1"
    local value="$2"
    local status_file="$project_dir/.project_status"
    
    if [ ! -f "$status_file" ]; then
        error_exit "Project status file not found: $status_file"
    fi
    
    # Create temporary file with updated status
    jq "${key} = ${value}" "$status_file" > "${status_file}.tmp"
    mv "${status_file}.tmp" "$status_file"
}

# User interaction
confirm() {
    local message="$1"
    local response
    
    while true; do
        read -p "$message (y/n): " response
        case "$response" in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "Please answer yes or no.";;
        esac
    done
}

# Git operations
commit_to_local_git() {
    local message="$1"
    local force_push="$2"
    
    if [ ! -d ".git" ]; then
        log "Not a git repository, skipping commit"
        return 1
    fi
    
    git add .
    git commit -m "$message" || {
        log "Nothing to commit or commit failed"
        return 1
    }
    
    if [ "$force_push" = true ]; then
        local remote=$(git remote 2>/dev/null | head -n1)
        if [ -n "$remote" ]; then
            git push "$remote" $(git branch --show-current) || {
                warn "Failed to push to remote"
                return 1
            }
        else
            warn "No remote repository configured"
        fi
    fi
    
    return 0
}

# Secret tagging functionality
tag_secrets() {
    local target="$1"
    local message="$2"
    
    if [ ! -e "$target" ]; then
        error_exit "Target path does not exist: $target"
    fi
    
    log "Tagging secrets in: $target"
    
    # Create .secrets_tagged file to track what's been tagged
    echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ'): Tagged secrets in $target" >> .secrets_tagged
    
    # Commit to local git only
    if [ -d ".git" ]; then
        git add .secrets_tagged
        git commit -m "${message:-"Tagged secrets in $target"}" || true
    fi
}

# Permission checking
check_permissions() {
    local target="${1:-.}"
    local issues=()
    
    log "Checking file permissions for: $target"
    
    # Check for overly permissive files
    while IFS= read -r -d '' file; do
        local perms=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%A' "$file" 2>/dev/null)
        if [[ "$perms" =~ ^[0-9]{3}$ ]]; then
            # Check for world-writable files
            if [[ "${perms:2:1}" -ge "2" ]]; then
                issues+=("$file: world-writable ($perms)")
            fi
            # Check for executable files that shouldn't be
            if [[ "$file" =~ \.(json|txt|md|yml|yaml)$ ]] && [[ "${perms:2:1}" -ge "1" ]]; then
                issues+=("$file: executable config file ($perms)")
            fi
        fi
    done < <(find "$target" -type f -print0 2>/dev/null)
    
    if [ ${#issues[@]} -gt 0 ]; then
        warn "Permission issues found:"
        printf '%s\n' "${issues[@]}"
        return 1
    else
        log "No permission issues found"
        return 0
    fi
}

# Generate Terraform configuration
generate_terraform_config() {
    local terraform_dir="$project_dir/terraform"
    log "Generating Terraform configuration in $terraform_dir"
    
    # Main configuration file
    cat > "$terraform_dir/main.tf" <<- EOL
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Environment = var.environment
      Project     = var.project_name
      ManagedBy   = "deploy-setup"
    }
  }
}
EOL

    # Variables file
    cat > "$terraform_dir/variables.tf" <<- EOL
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "development"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "$project_name"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "key_name" {
  description = "AWS key pair name"
  type        = string
  default     = "deploy-key"
}
EOL

    # Generate EC2 configuration if needed
    if [ "$USE_EC2" = true ]; then
        cat > "$terraform_dir/ec2.tf" <<- EOL
# VPC and networking
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "\${var.project_name}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "\${var.project_name}-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "\${var.project_name}-public-subnet"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "\${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security group
resource "aws_security_group" "web" {
  name        = "\${var.project_name}-web-sg"
  description = "Security group for web servers"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "\${var.project_name}-web-sg"
  }
}

# EC2 instance
resource "aws_instance" "web" {
  ami                    = data.aws_ami.debian.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  vpc_security_group_ids = [aws_security_group.web.id]
  subnet_id              = aws_subnet.public.id

  user_data = base64encode(templatefile("\${path.module}/user-data.sh", {
    project_type = "$PROJECT_LANG"
  }))

  tags = {
    Name = "\${var.project_name}-web"
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "debian" {
  most_recent = true
  owners      = ["136693071363"] # Debian

  filter {
    name   = "name"
    values = ["debian-12-amd64-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}
EOL

        # Generate user data script
        cat > "$terraform_dir/user-data.sh" <<- EOL
#!/bin/bash

set -euo pipefail

# Update system
apt-get update
apt-get upgrade -y

# Install common packages
apt-get install -y curl wget git nginx

# Project-specific setup
case "${project_type}" in
    "node")
        curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
        apt-get install -y nodejs
        npm install -g pm2
        ;;
    "python")
        apt-get install -y python3 python3-pip python3-venv
        ;;
    "php")
        apt-get install -y php php-fpm php-mysql php-curl php-gd php-mbstring php-xml php-zip
        ;;
esac

# Configure nginx
systemctl enable nginx
systemctl start nginx

# Create project directory
mkdir -p /var/www/html/app
chown -R www-data:www-data /var/www/html

echo "User data script completed" >> /var/log/user-data.log
EOL
    fi

    # Generate ECS configuration if needed
    if [ "$USE_ECS" = true ]; then
        cat > "$terraform_dir/ecs.tf" <<- EOL
# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "\${var.project_name}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "\${var.project_name}-cluster"
  }
}

# ECS Task Definition
resource "aws_ecs_task_definition" "app" {
  family                   = "\${var.project_name}-task"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = "256"
  memory                   = "512"
  execution_role_arn       = aws_iam_role.ecs_execution.arn

  container_definitions = jsonencode([
    {
      name  = "\${var.project_name}-container"
      image = "nginx:latest"  # Replace with your application image
      
      portMappings = [
        {
          containerPort = 80
          protocol      = "tcp"
        }
      ]
      
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.app.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "ecs"
        }
      }
    }
  ])
}

# ECS Service
resource "aws_ecs_service" "app" {
  name            = "\${var.project_name}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = $ECS_NUM
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = [aws_subnet.public.id]
    security_groups = [aws_security_group.web.id]
    assign_public_ip = true
  }

  depends_on = [aws_iam_role_policy_attachment.ecs_execution]
}

# IAM role for ECS execution
resource "aws_iam_role" "ecs_execution" {
  name = "\${var.project_name}-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_execution" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# CloudWatch log group
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/\${var.project_name}"
  retention_in_days = 7
}
EOL
    fi

    # Generate RDS configuration if needed
    if [ "$USE_RDS" = true ]; then
        cat > "$terraform_dir/rds.tf" <<- EOL
# RDS subnet group
resource "aws_db_subnet_group" "main" {
  name       = "\${var.project_name}-db-subnet-group"
  subnet_ids = [aws_subnet.public.id, aws_subnet.private.id]

  tags = {
    Name = "\${var.project_name}-db-subnet-group"
  }
}

# Private subnet for RDS
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = data.aws_availability_zones.available.names[1]

  tags = {
    Name = "\${var.project_name}-private-subnet"
  }
}

# Security group for RDS
resource "aws_security_group" "rds" {
  name        = "\${var.project_name}-rds-sg"
  description = "Security group for RDS"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  tags = {
    Name = "\${var.project_name}-rds-sg"
  }
}

# RDS instance
resource "aws_db_instance" "main" {
  identifier = "\${var.project_name}-db"
  
  engine         = "${RDS_TYPE:-mysql}"
  engine_version = "${RDS_TYPE:-mysql}" == "mysql" ? "8.0" : "13.7"
  instance_class = "db.t3.micro"
  
  allocated_storage = 20
  storage_type      = "gp2"
  
  db_name  = replace(var.project_name, "-", "_")
  username = "admin"
  password = "changeme123!"  # Use AWS Secrets Manager in production
  
  vpc_security_group_ids = [aws_security_group.rds.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  
  skip_final_snapshot = true
  
  tags = {
    Name = "\${var.project_name}-db"
  }
}
EOL
    fi

    # Generate S3 configuration if needed
    if [ "$NEED_S3" = true ]; then
        cat > "$terraform_dir/s3.tf" <<- EOL
# S3 bucket
resource "aws_s3_bucket" "main" {
  bucket = "\${var.project_name}-\${random_id.bucket_suffix.hex}"

  tags = {
    Name = "\${var.project_name}-bucket"
  }
}

resource "aws_s3_bucket_versioning" "main" {
  bucket = aws_s3_bucket.main.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}
EOL
    fi

    # Generate Load Balancer configuration if needed
    if [ "$NEED_ELB" = true ]; then
        cat > "$terraform_dir/elb.tf" <<- EOL
# Application Load Balancer
resource "aws_lb" "main" {
  name               = "\${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets           = [aws_subnet.public.id, aws_subnet.private.id]

  enable_deletion_protection = false

  tags = {
    Name = "\${var.project_name}-alb"
  }
}

# ALB Security Group
resource "aws_security_group" "alb" {
  name        = "\${var.project_name}-alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "\${var.project_name}-alb-sg"
  }
}

# Target Group
resource "aws_lb_target_group" "main" {
  name     = "\${var.project_name}-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    unhealthy_threshold = 2
    timeout             = 30
    interval            = 60
    path                = "/"
    matcher             = "200"
  }

  tags = {
    Name = "\${var.project_name}-tg"
  }
}

# ALB Listener
resource "aws_lb_listener" "main" {
  load_balancer_arn = aws_lb.main.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}
EOL

        # Attach targets to load balancer
        if [ "$USE_EC2" = true ]; then
            cat >> "$terraform_dir/elb.tf" <<- EOL

# Attach EC2 instance to target group
resource "aws_lb_target_group_attachment" "main" {
  target_group_arn = aws_lb_target_group.main.arn
  target_id        = aws_instance.web.id
  port             = 80
}
EOL
        fi
    fi

    # Outputs file
    cat > "$terraform_dir/outputs.tf" <<- EOL
output "project_name" {
  description = "Project name"
  value       = var.project_name
}
EOL

    if [ "$USE_EC2" = true ]; then
        cat >> "$terraform_dir/outputs.tf" <<- EOL

output "instance_ip" {
  description = "Public IP of EC2 instance"
  value       = aws_instance.web.public_ip
}

output "instance_dns" {
  description = "Public DNS of EC2 instance"
  value       = aws_instance.web.public_dns
}
EOL
    fi

    if [ "$NEED_ELB" = true ]; then
        cat >> "$terraform_dir/outputs.tf" <<- EOL

output "load_balancer_dns" {
  description = "DNS name of the load balancer"
  value       = aws_lb.main.dns_name
}
EOL
    fi

    if [ "$USE_RDS" = true ]; then
        cat >> "$terraform_dir/outputs.tf" <<- EOL

output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.main.endpoint
}
EOL
    fi

    if [ "$NEED_S3" = true ]; then
        cat >> "$terraform_dir/outputs.tf" <<- EOL

output "s3_bucket" {
  description = "S3 bucket name"
  value       = aws_s3_bucket.main.bucket
}
EOL
    fi
}

# Generate Ansible playbooks
generate_ansible_playbooks() {
    local ansible_dir="$project_dir/ansible"
    log "Generating Ansible playbooks in $ansible_dir"
    
    # Main playbook
    cat > "$ansible_dir/site.yml" <<- EOL
---
- hosts: all
  become: yes
  vars:
    project_name: $project_name
    project_type: $PROJECT_LANG
    app_user: app
    app_dir: /var/www/html/app
    
  roles:
    - common
    - security
    - nginx
    - $PROJECT_LANG
    - deploy

  post_tasks:
    - name: Ensure application is running
      service:
        name: nginx
        state: started
        enabled: yes
EOL

    # Inventory file
    cat > "$ansible_dir/inventory" <<- EOL
[web]
# Add your server IPs here
# 192.168.1.100 ansible_user=admin ansible_ssh_private_key_file=~/.ssh/deploy-key

[web:vars]
ansible_python_interpreter=/usr/bin/python3
EOL

    # Create roles directory structure
    for role in common security nginx $PROJECT_LANG deploy; do
        mkdir -p "$ansible_dir/roles/$role/{tasks,templates,files,vars,defaults,handlers}"
        
        # Create main task file for each role
        cat > "$ansible_dir/roles/$role/tasks/main.yml" <<- EOL
---
# Tasks for $role role
- name: $role tasks placeholder
  debug:
    msg: "Executing $role role tasks"
EOL
    done
    
    # Common role tasks
    cat > "$ansible_dir/roles/common/tasks/main.yml" <<- EOL
---
- name: Update package cache
  apt:
    update_cache: yes
    cache_valid_time: 3600
  when: ansible_os_family == "Debian"

- name: Install common packages
  package:
    name:
      - curl
      - wget
      - git
      - htop
      - vim
      - unzip
    state: present

- name: Create application user
  user:
    name: "{{ app_user }}"
    shell: /bin/bash
    home: "/home/{{ app_user }}"
    create_home: yes

- name: Create application directory
  file:
    path: "{{ app_dir }}"
    state: directory
    owner: "{{ app_user }}"
    group: "{{ app_user }}"
    mode: '0755'
EOL

    # Security role tasks
    cat > "$ansible_dir/roles/security/tasks/main.yml" <<- EOL
---
- name: Configure SSH security
  lineinfile:
    path: /etc/ssh/sshd_config
    regexp: "^#?{{ item.key }}"
    line: "{{ item.key }} {{ item.value }}"
    backup: yes
  with_items:
    - { key: "PermitRootLogin", value: "no" }
    - { key: "PasswordAuthentication", value: "no" }
    - { key: "PubkeyAuthentication", value: "yes" }
  notify: restart sshd

- name: Install and configure UFW
  package:
    name: ufw
    state: present

- name: Configure UFW default policies
  ufw:
    direction: "{{ item.direction }}"
    policy: "{{ item.policy }}"
  with_items:
    - { direction: 'incoming', policy: 'deny' }
    - { direction: 'outgoing', policy: 'allow' }

- name: Allow SSH through UFW
  ufw:
    rule: allow
    port: ssh

- name: Allow HTTP through UFW
  ufw:
    rule: allow
    port: '80'

- name: Allow HTTPS through UFW
  ufw:
    rule: allow
    port: '443'

- name: Enable UFW
  ufw:
    state: enabled
EOL

    # Add handler for SSH restart
    cat > "$ansible_dir/roles/security/handlers/main.yml" <<- EOL
---
- name: restart sshd
  service:
    name: ssh
    state: restarted
EOL

    # Nginx role tasks
    cat > "$ansible_dir/roles/nginx/tasks/main.yml" <<- EOL
---
- name: Install Nginx
  package:
    name: nginx
    state: present

- name: Create Nginx configuration
  template:
    src: nginx.conf.j2
    dest: /etc/nginx/sites-available/{{ project_name }}
    backup: yes
  notify: restart nginx

- name: Enable Nginx site
  file:
    src: /etc/nginx/sites-available/{{ project_name }}
    dest: /etc/nginx/sites-enabled/{{ project_name }}
    state: link
  notify: restart nginx

- name: Remove default Nginx site
  file:
    path: /etc/nginx/sites-enabled/default
    state: absent
  notify: restart nginx

- name: Start and enable Nginx
  service:
    name: nginx
    state: started
    enabled: yes
EOL

    # Nginx configuration template
    cat > "$ansible_dir/roles/nginx/templates/nginx.conf.j2" <<- EOL
server {
    listen 80;
    server_name {{ ansible_default_ipv4.address }};
    
    root {{ app_dir }};
    index index.html index.php;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    {% if project_type == 'php' %}
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php-fpm.sock;
    }
    {% endif %}
    
    {% if project_type == 'node' %}
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
    }
    {% endif %}
    
    {% if project_type == 'python' %}
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    {% endif %}
}
EOL

    # Nginx handler
    cat > "$ansible_dir/roles/nginx/handlers/main.yml" <<- EOL
---
- name: restart nginx
  service:
    name: nginx
    state: restarted
EOL

    # Language-specific role tasks
    case "$PROJECT_LANG" in
        "node")
            cat > "$ansible_dir/roles/node/tasks/main.yml" <<- EOL
---
- name: Install Node.js repository
  shell: curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
  args:
    creates: /etc/apt/sources.list.d/nodesource.list

- name: Install Node.js
  package:
    name: nodejs
    state: present

- name: Install PM2 globally
  npm:
    name: pm2
    global: yes

- name: Install application dependencies
  npm:
    path: "{{ app_dir }}"
  become_user: "{{ app_user }}"

- name: Create PM2 ecosystem file
  template:
    src: ecosystem.config.js.j2
    dest: "{{ app_dir }}/ecosystem.config.js"
    owner: "{{ app_user }}"
    group: "{{ app_user }}"
EOL

            cat > "$ansible_dir/roles/node/templates/ecosystem.config.js.j2" <<- 'EOL'
module.exports = {
  apps: [{
    name: '{{ project_name }}',
    script: './app.js',
    cwd: '{{ app_dir }}',
    instances: 1,
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production',
      PORT: 3000
    }
  }]
};
EOL
            ;;
            
        "python")
            cat > "$ansible_dir/roles/python/tasks/main.yml" <<- EOL
---
- name: Install Python and dependencies
  package:
    name:
      - python3
      - python3-pip
      - python3-venv
    state: present

- name: Create Python virtual environment
  command: python3 -m venv {{ app_dir }}/venv
  args:
    creates: "{{ app_dir }}/venv"
  become_user: "{{ app_user }}"

- name: Install Python requirements
  pip:
    requirements: "{{ app_dir }}/requirements.txt"
    virtualenv: "{{ app_dir }}/venv"
  become_user: "{{ app_user }}"
  when: requirements_file.stat.exists

- name: Check for requirements.txt
  stat:
    path: "{{ app_dir }}/requirements.txt"
  register: requirements_file

- name: Create systemd service for Python app
  template:
    src: python-app.service.j2
    dest: "/etc/systemd/system/{{ project_name }}.service"
  notify: restart python app
EOL

            cat > "$ansible_dir/roles/python/templates/python-app.service.j2" <<- EOL
[Unit]
Description={{ project_name }} Python Application
After=network.target

[Service]
Type=simple
User={{ app_user }}
WorkingDirectory={{ app_dir }}
Environment=PATH={{ app_dir }}/venv/bin
ExecStart={{ app_dir }}/venv/bin/python app.py
Restart=always

[Install]
WantedBy=multi-user.target
EOL

            cat > "$ansible_dir/roles/python/handlers/main.yml" <<- EOL
---
- name: restart python app
  systemd:
    name: "{{ project_name }}"
    state: restarted
    daemon_reload: yes
    enabled: yes
EOL
            ;;
            
        "php")
            cat > "$ansible_dir/roles/php/tasks/main.yml" <<- EOL
---
- name: Install PHP and extensions
  package:
    name:
      - php
      - php-fpm
      - php-mysql
      - php-curl
      - php-gd
      - php-mbstring
      - php-xml
      - php-zip
      - composer
    state: present

- name: Start and enable PHP-FPM
  service:
    name: php8.1-fpm
    state: started
    enabled: yes

- name: Install Composer dependencies
  composer:
    command: install
    working_dir: "{{ app_dir }}"
  become_user: "{{ app_user }}"
  when: composer_file.stat.exists

- name: Check for composer.json
  stat:
    path: "{{ app_dir }}/composer.json"
  register: composer_file
EOL
            ;;
    esac

    # Deploy role tasks
    cat > "$ansible_dir/roles/deploy/tasks/main.yml" <<- EOL
---
- name: Sync application files
  synchronize:
    src: "{{ playbook_dir }}/../"
    dest: "{{ app_dir }}/"
    delete: yes
    recursive: yes
    rsync_opts:
      - "--exclude=.git"
      - "--exclude=terraform"
      - "--exclude=ansible"
      - "--exclude=node_modules"
      - "--exclude=__pycache__"
      - "--exclude=.env"
  become_user: "{{ app_user }}"

- name: Set correct ownership
  file:
    path: "{{ app_dir }}"
    owner: "{{ app_user }}"
    group: "{{ app_user }}"
    recurse: yes

- name: Restart services after deployment
  service:
    name: "{{ item }}"
    state: restarted
  with_items:
    - nginx
EOL

    # Ansible configuration file
    cat > "$ansible_dir/ansible.cfg" <<- EOL
[defaults]
inventory = inventory
host_key_checking = False
retry_files_enabled = False
gathering = smart
fact_caching = memory

[ssh_connection]
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
pipelining = True
EOL
}
# Script for course CC617x - Cloud Computing Security
# IaC - BallotOnLine Security
# USMx - edX
# January 2021
# Hugo Aquino, Panama

# Before execute this script, execute "aws configure" in order to enable 
# AWS Access Key ID
# AWS Secret Access Key
# Default region name
# Default output format

# Generate a key executing
# "ssh-keygen"
# Save on the directory where you will run this script: <absolute_path>/cc617x-key-iac
# The key name must be cc617x-key-iac.pub, save on the directory where you will run this script <absolute_path>
# Left in blank "passphrase"

# This script runs on Terraform v0.13.5
# To install this version these are steps:
# wget https://releases.hashicorp.com/terraform/0.13.5/terraform_0.13.5_linux_amd64.zip
# unzip terraform_0.13.5_linux_amd64.zip
# sudo mv terraform /usr/local/bin/
# terraform --version

# The first time the script runs, Terraform has be intilized with "terraform apply"

# To run the script type: 

# If only the e-mail where the notifications will be has to be defined: 
# terraform apply -var "email=<email_address>"

# If in addition to the notifications the amount of default instances must be changed:
# terraform apply -var "minimum=<minimum_instances>" -var "maximum=<maximum_instances> -var "email=<email_address>"

# The script will run in Terraform version 0.13
terraform {
  required_version = ">= 0.13"
}

# Variable to define the minimum and maximum amount of instances to be created
variable minimum {
  default = 2
}

variable maximum {
  default = 3
}

# Variable to define the email where the notifications will be sent
variable email {
}

# AWS deployment
provider "aws" {
  profile = "default"
  region  = "us-west-2"
}

# To get Availability Zones info
data "aws_availability_zones" "all" {}

# Key generated
resource "aws_key_pair" "cc617x-key-iac" {
  key_name   = "cc617x-key-iac"
  public_key = file("cc617x-key-iac.pub")
}

# Getting information from the environment
# VPC
data "aws_vpc" "default" {
  default = true
}

# Security Group
data "aws_security_group" "default" {
  vpc_id = data.aws_vpc.default.id
}

# Subnets
data "aws_subnet_ids" "all" {
  vpc_id = data.aws_vpc.default.id
}

# Availability Zones
data "aws_availability_zones" "all_zones" {}

# Application Load balancer
resource "aws_alb" "alb" {  
  name            = "CC617x-alb"  
  subnets         = data.aws_subnet_ids.all.ids
  security_groups = [data.aws_security_group.default.id]
  tags = {    
    Name    = "CC617x-alb"    
  }   
  access_logs {    
    bucket = "CC617x_bucket"    
    prefix = "ELB-logs"  
  }
}

# Print Load Balancer DNS name
output "alb_dns_name" {
  value = aws_alb.alb.dns_name
}

# ALB target group
resource "aws_alb_target_group" "alb_target_group" {  
  name     = "CC617x"
  port     = 80  
  protocol = "HTTP"  
  vpc_id   = data.aws_vpc.default.id
  tags = {    
    name = "CC617x_alb_target_group"    
  }   
  
  health_check {    
    healthy_threshold   = 3    
    unhealthy_threshold = 10    
    timeout             = 5    
    interval            = 10    
    port                = 80
    protocol            = "HTTP"
  }
}

# ALB Listener
resource "aws_alb_listener" "alb_listener" {  
  load_balancer_arn = aws_alb.alb.arn  
  port              = 80  
  protocol          = "HTTP"
  default_action {    
    type             = "forward"  
    target_group_arn = aws_alb_target_group.alb_target_group.arn
  }
}

# Create Auto Scaling Group integrating the Lauch Configuration
resource "aws_autoscaling_group" "CC617x" {
  name                 = "CC617x"
  min_size             = var.minimum
  desired_capacity     = var.minimum
  max_size             = var.maximum
  availability_zones   = data.aws_availability_zones.all.names
  launch_configuration = aws_launch_configuration.CC617x.name
  target_group_arns    = [aws_alb_target_group.alb_target_group.arn]
}

# Launch Configuration
resource "aws_launch_configuration" "CC617x" {
  name            = "CC617x"
  image_id        =  "ami-07b919afaa5833920" #AMI with the website files
  instance_type   = "t2.micro"
  key_name        = "cc617x-key-iac"
  security_groups = [data.aws_security_group.default.id]
  lifecycle {
    create_before_destroy = true
  }
}

# Regex pattern set
resource "aws_wafv2_regex_pattern_set" "CC617x" {
  name        = "CC617x"
  scope       = "REGIONAL"
  description = "CC617x Regular expression definition"

  regular_expression {
    regex_string = "[Bb][Oo][Tt]"
  }

  regular_expression {
    regex_string = "[Bb][o0][Tt]"
  }

  regular_expression {
    regex_string = "[Bb][Aa][Dd][ ]*[Bb][oO][Tt]"
  }

  regular_expression {
    regex_string = "[Bb][Aa][Dd]"
  }

  regular_expression {
    regex_string = "[Hh][Aa][Cc][Kk][Ee][Rr]"
  }

}

# Define IP Set
resource "aws_wafv2_ip_set" "own_public_ip" {
  name               = "OwnPublicIP"
  description        = "Public IP"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = ["1.1.1.1/32"]
}

# Define WAF Rule group
resource "aws_wafv2_rule_group" "CC617x" {
  description = "CC617x Rule group definition"
  name        = "CC617x"
  scope       = "REGIONAL"
  capacity    = 80

  # Filter by country
  rule {
    name     = "CountryBlocked"
    priority = 1

    action {
      block {}
    }

    statement {
      geo_match_statement {
        country_codes = ["MX","DE","NL","CN","IN","IQ","PL"]
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CountryBlocked"
      sampled_requests_enabled   = true
    }
  }

  # Filter by size in a specific variable on query string
  rule {
    name     = "QueryArgument"
    priority = 2

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 10

        field_to_match {
           single_query_argument {
              name = "username"
           }
        }

        text_transformation {
           type     = "NONE"
           priority = 2
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "QueryArgument"
      sampled_requests_enabled   = true
    }
  }

  # Filter by word
  rule {
    name     = "WordBlocked"
    priority = 3

    action {
      block {}
    }

    statement {
      byte_match_statement {
        positional_constraint = "CONTAINS"
        search_string         = "xxx"

        field_to_match {
           all_query_arguments {}
        }

        text_transformation {
           type     = "LOWERCASE"
           priority = 3
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "WordBlocked"
      sampled_requests_enabled   = true
    }
  }

  # Filter by word
  rule {
    name     = "ArgumentSize"
    priority = 4

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        comparison_operator = "GT"
        size                = 15

        field_to_match {
           all_query_arguments {}
        }

        text_transformation {
           type     = "COMPRESS_WHITE_SPACE"
           priority = 4
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "ArgumentSize"
      sampled_requests_enabled   = true
    }
  }

  # Filter by Regular Expression
  rule {
    name     = "RegexFilter"
    priority = 5

    action {
      block {}
    }

    statement {
      regex_pattern_set_reference_statement {
         arn = aws_wafv2_regex_pattern_set.CC617x.arn

        field_to_match {
           query_string {}
        }

        text_transformation {
           type     = "NONE"
           priority = 5
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RegexFilter"
      sampled_requests_enabled   = true
    }
  }

  # Filter by PublicIP
  rule {
    name     = "OwnPublicIP"
    priority = 6

    action {
      block {}
    }

    statement {
        ip_set_reference_statement {       
           arn = aws_wafv2_ip_set.own_public_ip.arn
        }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "OwnPublicIP"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "CC617x"
    sampled_requests_enabled   = true
  }

}

# Define Web ACL
resource "aws_wafv2_web_acl" "CC617x" {
  description = "CC617x Web ACL"
  name        = "CC617x"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "CC617x"
    priority = 2

    override_action {
      none {}
    }

    statement {
          rule_group_reference_statement {
             arn = aws_wafv2_rule_group.CC617x.arn
          }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CC617x"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "CC617x"
    sampled_requests_enabled   = true
  }
}

# Associate the Web ACL
resource "aws_wafv2_web_acl_association" "CC617x" {
  resource_arn = aws_alb.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.CC617x.arn
}

# Create SNS for notifications
resource "aws_sns_topic" "notification" {
  name = "notification"

  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF

  provisioner "local-exec" {
    command = "aws sns subscribe --topic-arn ${self.arn} --protocol email --notification-endpoint ${var.email}"
  }
}

# Generate alarms in CloudWatch

# ALB request count
resource "aws_cloudwatch_metric_alarm" "CC617x_RequestCount" {
  alarm_name          = "CC617x_RequestCount"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "RequestCount"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  statistic           = "Sum"
  threshold           = "2500"
  alarm_description   = "Alarm generated when request count threshold is exceeded"
  actions_enabled     = "true"
  alarm_actions       = [aws_sns_topic.notification.arn]

  dimensions = {
    TargetGroup  = aws_alb_target_group.alb_target_group.arn_suffix
    LoadBalancer = aws_alb.alb.arn_suffix
  }

}

# WAF total passed requests
resource "aws_cloudwatch_metric_alarm" "CC617x_WAF_passed" {
  alarm_name          = "CC617x_WAF_passed"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "PassedRequests"
  namespace           = "AWS/WAFV2"
  period              = "60"
  statistic           = "Average"
  threshold           = "40"
  alarm_description   = "Alarm generated when passed threshold is exceeded"
  actions_enabled     = "true"
  alarm_actions       = [aws_sns_topic.notification.arn]
  treat_missing_data  = "missing"

  dimensions = {
     RuleGroup    = "CC617x"
     Region       = "us-west-2"
     Rule         = "ALL"
  }

}

# WAF total blocked requests
resource "aws_cloudwatch_metric_alarm" "CC617x_WAF_blocked" {
  alarm_name          = "CC617x_WAF_blocked"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "60"
  statistic           = "Average"
  threshold           = "200"
  alarm_description   = "Alarm generated when blocked threshold is exceeded"
  actions_enabled     = "true"
  alarm_actions       = [aws_sns_topic.notification.arn]
  treat_missing_data  = "missing"

  dimensions = {
     RuleGroup    = "CC617x"
     Region       = "us-west-2"
     Rule         = "ALL"
  }

}

# Blocked request from "CountryBlocked" rule
resource "aws_cloudwatch_metric_alarm" "CC617x_WAF_country_blocked" {
  alarm_name          = "CC617x_WAF_country_blocked"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "60"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "Alarm generated when country blocked threshold is exceeded"
  actions_enabled     = "true"
  alarm_actions       = [aws_sns_topic.notification.arn]
  treat_missing_data  = "missing"

  dimensions = {
     RuleGroup    = "CC617x"
     Region       = "us-west-2"
     Rule         = "CountryBlocked"
  }

}

# Blocked request from "QueryArgument" rule
resource "aws_cloudwatch_metric_alarm" "CC617x_WAF_query_argument" {
  alarm_name          = "CC617x_WAF_query_argument"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "60"
  statistic           = "Average"
  threshold           = "40"
  alarm_description   = "Alarm generated when query argument blocked threshold is exceeded"
  actions_enabled     = "true"
  alarm_actions       = [aws_sns_topic.notification.arn]
  treat_missing_data  = "missing"

  dimensions = {
     RuleGroup    = "CC617x"
     Region       = "us-west-2"
     Rule         = "QueryArgument"
  }

}

# Blocked request from "WordBlocked" rule
resource "aws_cloudwatch_metric_alarm" "CC617x_WAF_word_blocked" {
  alarm_name          = "CC617x_WAF_word_blocked"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "60"
  statistic           = "Average"
  threshold           = "50"
  alarm_description   = "Alarm generated when word block argument blocked threshold is exceeded"
  actions_enabled     = "true"
  alarm_actions       = [aws_sns_topic.notification.arn]
  treat_missing_data  = "missing"

  dimensions = {
     RuleGroup    = "CC617x"
     Region       = "us-west-2"
     Rule         = "WordBlocked"
  }

}

# Blocked request from "ArgumentSize" rule
resource "aws_cloudwatch_metric_alarm" "CC617x_WAF_argument_size" {
  alarm_name          = "CC617x_WAF_argument_size"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "60"
  statistic           = "Average"
  threshold           = "50"
  alarm_description   = "Alarm generated when argument size blocked threshold is exceeded"
  actions_enabled     = "true"
  alarm_actions       = [aws_sns_topic.notification.arn]
  treat_missing_data  = "missing"

  dimensions = {
     RuleGroup    = "CC617x"
     Region       = "us-west-2"
     Rule         = "ArgumentSize"
  }

}

# Blocked request from "RegexFilter" rule
resource "aws_cloudwatch_metric_alarm" "CC617x_WAF_regex_filter" {
  alarm_name          = "CC617x_WAF_regex_filter"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "60"
  statistic           = "Average"
  threshold           = "50"
  alarm_description   = "Alarm generated when regex filter blocked threshold is exceeded"
  actions_enabled     = "true"
  alarm_actions       = [aws_sns_topic.notification.arn]
  treat_missing_data  = "missing"

  dimensions = {
     RuleGroup    = "CC617x"
     Region       = "us-west-2"
     Rule         = "RegexFilter"
  }

}

# Blocked request from "OwnPublicIP" rule
resource "aws_cloudwatch_metric_alarm" "CC617x_WAF_own_ip_blocked" {
  alarm_name          = "CC617x_WAF_own_ip_blocked"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "60"
  statistic           = "Average"
  threshold           = "20"
  alarm_description   = "Alarm generated when own ip blocked threshold is exceeded"
  actions_enabled     = "true"
  alarm_actions       = [aws_sns_topic.notification.arn]
  treat_missing_data  = "missing"

  dimensions = {
     RuleGroup    = "CC617x"
     Region       = "us-west-2"
     Rule         = "OwnPublicIP"
  }

}

# Create a Cloudwatch dashboard
resource "aws_cloudwatch_dashboard" "CC617x-Dashboard" {
  dashboard_name = "CC617x-Dashboard"

  dashboard_body = <<EOF
{
  "widgets": [
    {
      "type": "metric",
      "x": 0,
      "y": 0,
      "width": 12,
      "height": 4,
      "properties": {
        "metrics": [
          [
            "AWS/WAFV2",
            "PassedRequests",
            "Region",
            "us-west-2",
            "Rule",
            "ALL",
            "RuleGroup",
            "CC617x"
          ]
        ],
        "period": 60,
        "stat": "Average",
        "region": "us-west-2",
        "title": "WAF - Passed Requests"
      }
    },
    {
      "type": "metric",
      "x": 13,
      "y": 0,
      "width": 12,
      "height": 4,
      "properties": {
        "metrics": [
          [
            "AWS/WAFV2",
            "BlockedRequests",
            "Region",
            "us-west-2",
            "Rule",
            "ALL",
            "RuleGroup",
            "CC617x"
          ]
        ],
        "period": 60,
        "stat": "Average",
        "region": "us-west-2",
        "title": "WAF - Blocked Requests"
      }
    },
    {
      "type": "metric",
      "x": 0,
      "y": 5,
      "width": 12,
      "height": 4,
      "properties": {
        "metrics": [
          [
            "AWS/WAFV2",
            "BlockedRequests",
            "Region",
            "us-west-2",
            "Rule",
            "CountryBlocked",
            "RuleGroup",
            "CC617x"
          ]
        ],
        "period": 60,
        "stat": "Average",
        "region": "us-west-2",
        "title": "WAF - Country Blocked Requests"
      }
    },
    {
      "type": "metric",
      "x": 13,
      "y": 5,
      "width": 12,
      "height": 4,
      "properties": {
        "metrics": [
          [
            "AWS/WAFV2",
            "BlockedRequests",
            "Region",
            "us-west-2",
            "Rule",
            "QueryArgument",
            "RuleGroup",
            "CC617x"
          ]
        ],
        "period": 60,
        "stat": "Average",
        "region": "us-west-2",
        "title": "WAF - Query Argument Requests"
      }
    },
    {
      "type": "metric",
      "x": 0,
      "y": 10,
      "width": 12,
      "height": 4,
      "properties": {
        "metrics": [
          [
            "AWS/WAFV2",
            "BlockedRequests",
            "Region",
            "us-west-2",
            "Rule",
            "WordBlocked",
            "RuleGroup",
            "CC617x"
          ]
        ],
        "period": 60,
        "stat": "Average",
        "region": "us-west-2",
        "title": "WAF - Word Blocked Requests"
      }
    },
    {
      "type": "metric",
      "x": 13,
      "y": 10,
      "width": 12,
      "height": 4,
      "properties": {
        "metrics": [
          [
            "AWS/WAFV2",
            "BlockedRequests",
            "Region",
            "us-west-2",
            "Rule",
            "ArgumentSize",
            "RuleGroup",
            "CC617x"
          ]
        ],
        "period": 60,
        "stat": "Average",
        "region": "us-west-2",
        "title": "WAF - Argument Size Requests"
      }
    },
    {
      "type": "metric",
      "x": 0,
      "y": 15,
      "width": 12,
      "height": 4,
      "properties": {
        "metrics": [
          [
            "AWS/WAFV2",
            "BlockedRequests",
            "Region",
            "us-west-2",
            "Rule",
            "RegexFilter",
            "RuleGroup",
            "CC617x"
          ]
        ],
        "period": 60,
        "stat": "Average",
        "region": "us-west-2",
        "title": "WAF - Regex Blocked Requests"
      }
    },
    {
      "type": "metric",
      "x": 13,
      "y": 15,
      "width": 12,
      "height": 4,
      "properties": {
        "metrics": [
          [
            "AWS/WAFV2",
            "BlockedRequests",
            "Region",
            "us-west-2",
            "Rule",
            "OwnPublicIP",
            "RuleGroup",
            "CC617x"
          ]
        ],
        "period": 60,
        "stat": "Average",
        "region": "us-west-2",
        "title": "WAF - Own Public IP Requests"
      }
    }
  ]
}
EOF
}

# Defining RDS with MySQL
module "db" {
  source  = "terraform-aws-modules/rds/aws"
  version = "~> 2.0"

  identifier = "cc617x"

  engine            = "mysql"
  engine_version    = "5.7.26"
  instance_class    = "db.t2.micro"
  allocated_storage = 5

  publicly_accessible = false

  name     = "cc617x"
  username = "cc617x"
  password = "YourPwdShouldBeLongAndSecure!"
  port     = "3306"

  iam_database_authentication_enabled = false
  multi_az                            = true
  vpc_security_group_ids              = [data.aws_security_group.default.id]
  maintenance_window                  = "Mon:00:00-Mon:03:00"
  backup_window                       = "03:00-06:00"
  backup_retention_period             = 0

  # Enhanced Monitoring - see example for details on how to create the role
  # by yourself, in case you don't want to create it automatically
  monitoring_interval    = "30"
  monitoring_role_name   = "RDSMonitoringRole"
  create_monitoring_role = true

  tags = {
    Owner       = "cc617x"
    Environment = "prod"
  }

  # DB subnet group
  subnet_ids = data.aws_subnet_ids.all.ids
  # DB parameter group
  family = "mysql5.7"

  # DB option group
  major_engine_version = "5.7"

  # Snapshot name upon DB deletion
  final_snapshot_identifier = "cc617x"

  # Database Deletion Protection
  deletion_protection = false

  parameters = [
    {
      name = "character_set_client"
      value = "utf8"
    },
    {
      name = "character_set_server"
      value = "utf8"
    }
  ]

  options = [
    {
      option_name = "MARIADB_AUDIT_PLUGIN"

      option_settings = [
        {
          name  = "SERVER_AUDIT_EVENTS"
          value = "CONNECT"
        },
        {
          name  = "SERVER_AUDIT_FILE_ROTATIONS"
          value = "37"
        },
      ]
    },
  ]
}

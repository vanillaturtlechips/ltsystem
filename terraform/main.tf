terraform {
  required_providers {
    aws = {
        source = "hashicorp/aws"
        version = "~> 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  image_tag = "latest"
}

provider "aws" {
    region = "ap-northeast-2"
}

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

provider "aws" {
  alias  = "us-east-1"
  region = "us-east-1"
}

resource "aws_secretsmanager_secret" "lts_db_password_secret" {
    name = "lts/db/password-go-stack"
    description = "RDS database password for LTS system"

    tags = {
        Name = "lts-db-password-secret"
    }
}

resource "aws_secretsmanager_secret_version" "lts_db_password_version" {
    secret_id = aws_secretsmanager_secret.lts_db_password_secret.id
    secret_string = "Password1234!"

    depends_on = [aws_secretsmanager_secret.lts_db_password_secret]
}


resource "aws_vpc" "lts_vpc" {
    cidr_block = "10.0.0.0/16" 
    
    tags = {
        Name = "lts_vpc"
    }
}

resource "aws_subnet" "lts_public_subnet" {
    vpc_id = aws_vpc.lts_vpc.id
    cidr_block = "10.0.1.0/24"
    availability_zone = "ap-northeast-2a"

    # 공인 ip 자동 할당
    map_public_ip_on_launch = true

    tags = {
        Name = "lts-public-subnet"
    }
}

resource "aws_subnet" "lts_public_subnet_2c" {
    vpc_id = aws_vpc.lts_vpc.id
    cidr_block = "10.0.4.0/24"
    availability_zone = "ap-northeast-2c"

    map_public_ip_on_launch = true

    tags = {
        Name = "lts-public-subnet-2c"
    }
}

resource "aws_route_table_association" "d" {
    subnet_id = aws_subnet.lts_public_subnet_2c.id
    route_table_id = aws_route_table.lts_route_table.id
}



resource "aws_internet_gateway" "lts_igw" {
    vpc_id = aws_vpc.lts_vpc.id

    tags = {
        Name = "lts-igw"
    }
}


resource "aws_route_table" "lts_route_table" {
    vpc_id = aws_vpc.lts_vpc.id

    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.lts_igw.id
    } 

    tags = {
        Name = "lts-public-rt"
    }
}

resource "aws_route_table_association" "a" {
    subnet_id = aws_subnet.lts_public_subnet.id
    route_table_id = aws_route_table.lts_route_table.id
}

resource "aws_security_group" "lts_bastion_sg" {
    name = "lts-server-sg"
    description = "Allow SSH inbound traffic for Bastion"
    vpc_id = aws_vpc.lts_vpc.id

    ingress {
        description = "SSH from my IP"
        from_port = 22
        to_port = 22
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }
    
    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "lts-bastion-sg"
    }
}

data "aws_ami" "amazon_linux" {
    most_recent = true
    owners = ["amazon"]
    filter {
        name = "name"
        values = ["amzn2-ami-hvm-*-x86_64-gp2"]

    }
}

resource "aws_eip" "lts_nat_eip" {
    domain = "vpc"

    tags = {
        Name = "lts-nat-eip"
    }
}

resource "aws_nat_gateway" "lts_nat_gw" {
    allocation_id = aws_eip.lts_nat_eip.id
    subnet_id = aws_subnet.lts_public_subnet.id

    tags = {
        Name = "lts-nat-gw"
    }

    depends_on = [aws_internet_gateway.lts_igw]
}

resource "aws_subnet" "lts_private_subnet" {
    vpc_id = aws_vpc.lts_vpc.id
    cidr_block = "10.0.2.0/24"
    availability_zone = "ap-northeast-2c"

    map_public_ip_on_launch = false

    tags = {
        Name = "lts-private-subnet"
    }
}

resource "aws_route_table" "lts_private_rt" {
    vpc_id = aws_vpc.lts_vpc.id

    route {
        cidr_block = "0.0.0.0/0"
        nat_gateway_id = aws_nat_gateway.lts_nat_gw.id
    } 
    tags = {
        Name = "lts-private-rt"
    }
}

resource "aws_route_table_association" "b" {
    subnet_id = aws_subnet.lts_private_subnet.id
    route_table_id = aws_route_table.lts_private_rt.id
}

resource "aws_instance" "lts_bastion" {
    ami = data.aws_ami.amazon_linux.id
    instance_type = "t2.micro"

    subnet_id = aws_subnet.lts_public_subnet.id

    vpc_security_group_ids = [aws_security_group.lts_bastion_sg.id]

    key_name = "lts-key-pair"

    tags = {
        Name = "lts-bastion-host"
    }

}

resource "aws_subnet" "lts_private_subnet_2a" {
    vpc_id = aws_vpc.lts_vpc.id
    cidr_block = "10.0.3.0/24" 
    availability_zone = "ap-northeast-2a"

    tags = {
        Name = "lts-private-subnet-2a"
    }
}

resource "aws_route_table_association" "c" {
    subnet_id = aws_subnet.lts_private_subnet_2a.id
    route_table_id = aws_route_table.lts_private_rt.id
}

resource "aws_db_subnet_group" "lts_db_subnet_group" {
    name = "lts-db-subnet-group"
    subnet_ids = [
        aws_subnet.lts_private_subnet.id,
        aws_subnet.lts_private_subnet_2a.id
    ]

    tags = {
        Name = "LTS DB Subnet Group"
    }
}

resource "aws_security_group" "lts_db_sg" {
    name = "lts-db-sg"
    description = "Allow MySQL traffic from lts_server_sg"
    vpc_id = aws_vpc.lts_vpc.id 
    
    ingress {
        description = "MySQL from App Server"
        from_port = 3306
        to_port = 3306
        protocol = "tcp"
    

    security_groups = [aws_security_group.lts_app_sg.id]
}
    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "lts-db-sg"
    }
}

resource "aws_db_instance" "lts_db" {
    identifier = "lts-db-mysql"
    allocated_storage = 20
    instance_class = "db.t3.micro"
    engine = "mysql"
    engine_version = "8.0"

    db_name = "lts_db"

    username = "admin"
    password = aws_secretsmanager_secret_version.lts_db_password_version.secret_string

    depends_on = [aws_secretsmanager_secret_version.lts_db_password_version]

    db_subnet_group_name = aws_db_subnet_group.lts_db_subnet_group.name
    vpc_security_group_ids = [aws_security_group.lts_db_sg.id]

    publicly_accessible = false

    skip_final_snapshot = true
}

resource "aws_security_group" "lts_alb_sg" {
    name = "lts-alb-sg"
    description = "Allow HTTP inbound traffic for ALB"
    vpc_id = aws_vpc.lts_vpc.id

    ingress {
        description = "HTTP from Internet"
        from_port = 80
        to_port = 80
        protocol = "tcp"
        cidr_blocks = ["0.0.0.0/0"]
    }

    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "lts-alb-sg"
    }
}

resource "aws_security_group" "lts_app_sg" {
    name = "lts-app-sg"
    description = "Allow traffic from ALB and Bastion"
    vpc_id = aws_vpc.lts_vpc.id

    ingress {
        description = "HTTP from ALB"
        from_port = 80
        to_port = 80
        protocol = "tcp"
        security_groups = [aws_security_group.lts_alb_sg.id]
    }

    ingress {
        description = "SSH from Bastion"
        from_port = 22
        to_port = 22
        protocol = "tcp"
        security_groups = [aws_security_group.lts_bastion_sg.id]
    }

    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "lts-app-sg"
    }
}


# resource "aws_launch_template" "lts_app_lt" {
#     name_prefix = "lts-app-"
#     image_id = data.aws_ami.amazon_linux.id
#     instance_type = "t2.micro"
#     key_name = "lts-key-pair"

#     vpc_security_group_ids = [aws_security_group.lts_app_sg.id]

#     # test server
# user_data = base64encode(<<-EOF
# #!/bin/bash
# yum update -y
# yum install -y httpd
# systemctl start httpd
# systemctl enable httpd
# echo "<h1>Hello from $(hostname -f)</h1>" > /var/www/html/index.html
# EOF
#     )

#     tags = {
#         Name = "lts-app-launch-template"
#     }
# }

resource "aws_lb" "lts_alb" {
    name = "lts-app-alb"
    internal = false
    load_balancer_type = "application"
    security_groups = [aws_security_group.lts_alb_sg.id]

    subnets         = [
        aws_subnet.lts_public_subnet.id,
        aws_subnet.lts_public_subnet_2c.id
    ]

    tags = {
        Name = "lts-app-alb"
    }
}

resource "aws_lb_target_group" "lts_app_tg" {
    name = "lts-app-tg"
    port = 80
    protocol = "HTTP"
    vpc_id = aws_vpc.lts_vpc.id

    # fargate는 인스턴스가 아닌 ip 타겟 타입이 필요함(트러블 슈팅)
    target_type = "ip"

    lifecycle {
        create_before_destroy = false
    }

    health_check {
        path = "/"
        port = "traffic-port"
    }

    tags = {
        Name = "lts-app-target-group"
    }
}

resource "aws_lb_listener" "lts_http_listener" {
    load_balancer_arn = aws_lb.lts_alb.arn
    port = "80"
    protocol = "HTTP"

    default_action {
        type = "forward"
        target_group_arn = aws_lb_target_group.lts_app_tg.arn
    }

    lifecycle {
    create_before_destroy = false
  }
}

resource "aws_ecs_cluster" "lts_cluster" {
    name = "lts-cluster"

    tags = {
        Name = "lts-ecs-cluster"
    }
}

resource "aws_ecr_repository" "lts_app_repo" {
    name = "lts-app-repo"

    image_tag_mutability = "MUTABLE"

    image_scanning_configuration {
        scan_on_push = true
    }

    tags = {
        Name = "lts-app-repo"
    }
}

resource "aws_iam_role_policy_attachment" "ecs_ecr_policy" {
    role = aws_iam_role.lts_ecs_task_execution_role.name
    policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}


resource "aws_iam_role" "lts_ecs_task_execution_role" {
    name = "lts-ecs-task-execution-role"

    assume_role_policy = jsonencode ({
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

# resource "aws_iam_role_policy_attachment" "lts_kinesis_lambda_policy" {
#     role = aws_iam_role.lts_ecs_task_execution_role.name
#     policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy" 
# }

resource "aws_iam_role_policy_attachment" "lts_ecs_task_execution_policy" {
  role       = aws_iam_role.lts_ecs_task_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy" 
}

resource "aws_ecs_task_definition" "lts_app_task" {
    family = "lts-app-task"
    network_mode = "awsvpc"
    requires_compatibilities = ["FARGATE"]
    cpu = 256
    memory = 512

    execution_role_arn = aws_iam_role.lts_ecs_task_execution_role.arn

    container_definitions = jsonencode([
        {
            name = "lts-app-container"
            image = "${data.aws_caller_identity.current.account_id}.dkr.ecr.${data.aws_region.current.name}.amazonaws.com/${aws_ecr_repository.lts_app_repo.name}:${local.image_tag}"
            essential = true
            portMappings = [
                {
                    containerPort = 80
                    hostPort = 80
                }
                ]

            environment = [
                {
                    name = "DATABASE_URL"
                    value = "mysql://admin:${aws_secretsmanager_secret_version.lts_db_password_version.secret_string}@${aws_db_instance.lts_db.endpoint}/${aws_db_instance.lts_db.db_name}"  
                }
                ]
            secrets = [
                {
                    name = "DB_PASSWORD_PLACEHOLDER"
                    valueFrom = aws_secretsmanager_secret.lts_db_password_secret.arn
                }
                ]

                logConfiguration = {
                    logDriver = "awslogs"
                    options = {
                        "awslogs-group" = "/ecs/lts-app"
                        "awslogs-region" = "ap-northeast-2"
                        "awslogs-stream-prefix" = "ecs"
                    }
                }
        }
    ])

    depends_on = [
        aws_ecr_repository.lts_app_repo,
        aws_iam_role_policy_attachment.ecs_secrets_attachment
    ]

}

resource "aws_cloudwatch_log_group" "lts_ecs_logs" {
    name = "/ecs/lts-app"

    tags = {
        Name = "lts-ecs-logs"
    }
}

resource "aws_ecs_service" "lts_app_service" {
    name = "lts_app_service"
    cluster = aws_ecs_cluster.lts_cluster.id
    task_definition = aws_ecs_task_definition.lts_app_task.arn

    desired_count = 2
    launch_type = "FARGATE"

    network_configuration {
        subnets = [
            aws_subnet.lts_private_subnet.id,
            aws_subnet.lts_private_subnet_2a.id
        ]

        security_groups = [aws_security_group.lts_app_sg.id]

        assign_public_ip = false
    }

    load_balancer {
        target_group_arn = aws_lb_target_group.lts_app_tg.arn
        container_name = "lts-app-container"
        container_port = 80
    }

    force_new_deployment = true

    health_check_grace_period_seconds = 300

}

resource "aws_kinesis_stream" "lts_traffic_stream" {
    name = "lts-traffic-stream-v2"
    shard_count = 1 # 일단 test

    tags = {
        Name = "lts-traffic-stream"
    }
}

resource "aws_iam_role" "lts_kinesis_lambda_role" {
    name = "lts-kinesis-lambda-role"

    assume_role_policy = jsonencode ({
        Version = "2012-10-17"
        Statement = [
            {
                Action  = "sts:AssumeRole"
                Effect = "Allow"
                Principal = {
                    Service = "lambda.amazonaws.com"
                }
            }
        ]
    })
}

# resource "aws_iam_role_policy_attachment" "lts_ecs_task_execution_policy" {
#     role = aws_iam_role.lts_kinesis_lambda_role.name

#     policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaKinesisExecutionRole"
# }

resource "aws_iam_role_policy_attachment" "lts_kinesis_lambda_policy" {
  role       = aws_iam_role.lts_kinesis_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaKinesisExecutionRole"
}

data "archive_file" "lts_consumer_lambda_zip" {
  type        = "zip"
  output_path = "${path.module}/lts_consumer_lambda.zip"

  source {
    content  = <<-EOF
    import base64
    import json
    import boto3
    import os
    import datetime

    S3_BUCKET_NAME = os.environ['S3_BUCKET_NAME']
    DYNAMO_TABLE_NAME = os.environ['DYNAMO_TABLE_NAME']

    s3_client = boto3.client('s3')
    dynamodb = boto3.resource('dynamodb')
    dynamo_table = dynamodb.Table(DYNAMO_TABLE_NAME)

    print('Loading function')

    def lambda_handler(event, context):
        print(f"Received {len(event['Records'])} records.")
        
        processed_records = 0
        
        for record in event['Records']:
            payload = None
            try:
                payload = base64.b64decode(record['kinesis']['data']).decode('utf-8')
                
                print(f"--- RAW PAYLOAD RECEIVED ---")
                print(f"Type: {type(payload)}")
                print(f"Payload: {payload}")
                print(f"--- END RAW PAYLOAD ---")

                data = json.loads(payload) 
                vehicle_id = data['VehicleID']

                now = datetime.datetime.now()
                s3_key = f"year={now.year}/month={now.month:02d}/day={now.day:02d}/{vehicle_id}-{now.timestamp()}.json"
                
                s3_client.put_object(
                    Bucket=S3_BUCKET_NAME,
                    Key=s3_key,
                    Body=payload
                )

                dynamo_table.put_item(
                    Item=data
                )
                
                print(f"Successfully processed and stored data for VehicleID: {vehicle_id}")
                processed_records += 1
                
            except Exception as e:
                print(f"!!! ERROR processing record !!!")
                print(f"Error: {e}")
                print(f"--- FAILED PAYLOAD ---")
                print(f"Type: {type(payload)}")
                print(f"Payload: {payload}")
                print(f"--- END FAILED PAYLOAD ---")

        return f"Successfully processed {processed_records} records."
    EOF
    filename = "lambda_function.py"
  }
}

resource "aws_lambda_function" "lts_kinesis_consumer" {
    function_name = "lts-kinesis-consumer"
    filename = data.archive_file.lts_consumer_lambda_zip.output_path
    source_code_hash = data.archive_file.lts_consumer_lambda_zip.output_base64sha256

    handler = "lambda_function.lambda_handler"
    runtime = "python3.11"
    role = aws_iam_role.lts_kinesis_lambda_role.arn

    timeout = 60

    environment {
        variables = {
            S3_BUCKET_NAME = aws_s3_bucket.lts_data_lake.id
            DYNAMO_TABLE_NAME = aws_dynamodb_table.lts_realtime_dashboard.name
        }
    }

    tags = {
        Name = "lts-kinesis-consumer"
    }
}

resource "aws_lambda_event_source_mapping" "lts_kinesis_trigger" {
    event_source_arn = aws_kinesis_stream.lts_traffic_stream.arn
    function_name = aws_lambda_function.lts_kinesis_consumer.arn

    starting_position = "LATEST"
}

resource "aws_s3_bucket" "lts_data_lake" {
    bucket_prefix = "lts-traffic-data-lake-"
    
    force_destroy = true

    tags = {
        Name = "lts-data-lake"
    }
}

resource "aws_dynamodb_table" "lts_realtime_dashboard" {
    name = "lts-realtime-dashboard"
    billing_mode = "PAY_PER_REQUEST"

    hash_key = "VehicleID"

    attribute {
        name = "VehicleID"
        type = "S"
    }

    tags = {
        Name = "lts-realtime-dashboard"
    }
}

resource "aws_iam_policy" "lts_lambda_db_policy" {
    name = "lts-lambda-db-write-policy"
    description = "Allow Lambda to write to S3 and DynamoDB"

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Action = "s3:PutObject"
                Resource = "${aws_s3_bucket.lts_data_lake.arn}/*"
            },
            {
                Effect = "Allow"
                Action = "dynamodb:PutItem"
                Resource = aws_dynamodb_table.lts_realtime_dashboard.arn
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "lts_lambda_db_attachment" {
    role = aws_iam_role.lts_kinesis_lambda_role.name
    policy_arn = aws_iam_policy.lts_lambda_db_policy.arn
}

resource "aws_glue_catalog_database" "lts_catalog_db" {
    name = "lts_traffic_data_catalog"
}

resource "aws_iam_role" "lts_glue_role" {
    name = "lts-glue-service-role"

    assume_role_policy = jsonencode ({
        Version = "2012-10-17"
        Statement = [
            {
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Principal = {
                    Service = "glue.amazonaws.com"
                }
            }
        ]
    })
}

resource "aws_iam_role_policy_attachment" "lts_glue_policy_attachment" {
    role = aws_iam_role.lts_glue_role.name
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_glue_crawler" "lts_s3_crawler" {
    name = "lts-s3-data-crawler"
    role = aws_iam_role.lts_glue_role.arn
    database_name = aws_glue_catalog_database.lts_catalog_db.name

    s3_target {
        path = "s3://${aws_s3_bucket.lts_data_lake.id}/"

        exclusions = [
          "glue-scripts/**",  # .py 스크립트 폴더 제외
          "glue-temp/**",     # 임시 파일 폴더 제외
          "processed/**"    # 향후 생성될 결과물 폴더 제외
        ]
    }

    configuration = jsonencode({
        Version = 1.0
        CrawlerOutput = {
            Partitions = { AddOrUpdateBehavior = "InheritFromTable"}
        },
        Grouping = {
            TableGroupingPolicy = "CombineCompatibleSchemas"
        }
    })

    schema_change_policy {
        update_behavior = "UPDATE_IN_DATABASE"
        delete_behavior = "LOG"
    }

    depends_on = [aws_iam_role_policy_attachment.lts_glue_s3_rw_attachment]
}

resource "aws_glue_job" "lts_etl_job" {
    name = "lts-traffic-etl-job"
    role_arn = aws_iam_role.lts_glue_role.arn

    glue_version = "5.0"

    number_of_workers = 2
    worker_type = "G.1X"

    command {
        name = "glueetl"
        script_location = "s3://${aws_s3_bucket.lts_data_lake.id}/${aws_s3_object.lts_glue_script.key}"
        python_version = "3"
    }

    default_arguments = {
        "--TempDir" = "s3://${aws_s3_bucket.lts_data_lake.id}/glue-temp/"
        "--job-bookmark-option" = "job-bookmark-enable"

        "--S3_OUTPUT_BUCKET" = aws_s3_bucket.lts_data_lake.id
    }

    depends_on = [aws_iam_role_policy_attachment.lts_glue_policy_attachment,
    aws_s3_object.lts_glue_script]
}

resource "aws_s3_object" "lts_glue_script" {
    bucket = aws_s3_bucket.lts_data_lake.id
    key = "glue-scripts/lts_etl_script.py"

    source = "${path.module}/lts_etl_script.py"

    etag = filemd5("${path.module}/lts_etl_script.py")
}


resource "aws_iam_policy" "lts_glue_s3_rw_policy" {
  name        = "lts-glue-s3-rw-policy"
  description = "Allow Glue role to read from the S3 data lake bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:GetObject", 
          "s3:ListBucket",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.lts_data_lake.arn,        
          "${aws_s3_bucket.lts_data_lake.arn}/*" 
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lts_glue_s3_rw_attachment" {
  role       = aws_iam_role.lts_glue_role.name
  policy_arn = aws_iam_policy.lts_glue_s3_rw_policy.arn
}

resource "aws_athena_workgroup" "lts_workgroup" {
    name = "lts-workgroup"

    force_destroy = true

    configuration {
        result_configuration {
            output_location = "s3://${aws_s3_bucket.lts_data_lake.id}/athena-results/"
        }
    }

    depends_on = [aws_s3_bucket.lts_data_lake]
}

resource "aws_glue_crawler" "lts_processed_crawler" {
    name = "lts-processed-data-crawler"

    role = aws_iam_role.lts_glue_role.arn

    database_name = aws_glue_catalog_database.lts_catalog_db.name

    s3_target {
        path = "s3://${aws_s3_bucket.lts_data_lake.id}/processed/"
    }

    schema_change_policy {
        update_behavior = "UPDATE_IN_DATABASE"
        delete_behavior = "LOG"
    }

    depends_on = [aws_iam_role_policy_attachment.lts_glue_s3_rw_attachment]
}

resource "aws_iam_role" "lts_sagemaker_role" {
    name = "lts-sagemaker-notebook-role"

    assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Action = "sts:AssumeRole"
                Effect = "Allow"
                Principal = {
                    Service = "sagemaker.amazonaws.com"
                }
            }
        ]
    })

    tags = {
        Name = "lts-sagemaker-role"
    }
}

resource "aws_iam_role_policy_attachment" "lts_sagemaker_policy" {
    role = aws_iam_role.lts_sagemaker_role.name
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
}

resource "aws_iam_role_policy" "lts_sagemaker_s3_access" {
    name = "lts-sagemaker-s3-data-lake-access"
    role = aws_iam_role.lts_sagemaker_role.id

    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect = "Allow"
                Action = [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket"
                ]
                Resource = [
                    aws_s3_bucket.lts_data_lake.arn,
                    "${aws_s3_bucket.lts_data_lake.arn}/*"
                ]
            }
        ]
    })
}

resource "aws_sagemaker_notebook_instance" "lts_notebook" {
    name = "lts-traffic-prediction-notebook"

    role_arn = aws_iam_role.lts_sagemaker_role.arn

    instance_type = "ml.t2.medium"

    depends_on = [aws_iam_role_policy.lts_sagemaker_s3_access]

    tags = {
        Name = "lts-ml-notebook"
    }
}

resource "aws_iam_role_policy_attachment" "lts_sagemaker_athena_policy" {
    role = aws_iam_role.lts_sagemaker_role.name

    policy_arn = "arn:aws:iam::aws:policy/AmazonAthenaFullAccess"
}

resource "aws_wafv2_web_acl_association" "lts_waf_alb_assoc" {
    resource_arn = aws_lb.lts_alb.arn

    web_acl_arn = aws_wafv2_web_acl.lts_waf_acl.arn
}

resource "aws_api_gateway_rest_api" "lts_api" {
    name = "lts-api-gateway"
    description = "Public-facing API for LTS System"

    binary_media_types = ["*/*/"]
}



resource "aws_api_gateway_method" "lts_api_root_get_method" {
  rest_api_id   = aws_api_gateway_rest_api.lts_api.id
  resource_id   = aws_api_gateway_rest_api.lts_api.root_resource_id
  http_method   = "GET"
  authorization = "NONE" # 인증 사용 안 함
}

resource "aws_api_gateway_integration" "lts_api_root_get_integration" {
  rest_api_id = aws_api_gateway_rest_api.lts_api.id
  resource_id = aws_api_gateway_rest_api.lts_api.root_resource_id
  http_method = aws_api_gateway_method.lts_api_root_get_method.http_method
  type                    = "HTTP_PROXY"
  integration_http_method = "GET" 
  uri                     = "http://${aws_lb.lts_alb.dns_name}/" 
  request_parameters = {
  }
}



resource "aws_api_gateway_resource" "lts_api_proxy" {
    
    rest_api_id = aws_api_gateway_rest_api.lts_api.id
    parent_id = aws_api_gateway_rest_api.lts_api.root_resource_id

    path_part = "{proxy+}"
}

resource "aws_api_gateway_method" "lts_api_proxy_method" {
    rest_api_id = aws_api_gateway_rest_api.lts_api.id
    resource_id = aws_api_gateway_resource.lts_api_proxy.id
    http_method = "ANY"
    authorization = "COGNITO_USER_POOLS"
    authorizer_id = aws_api_gateway_authorizer.lts_cognito_auth.id

    request_parameters = {

        "method.request.path.proxy" = true
    }
}

resource "aws_api_gateway_integration" "lts_api_proxy_integration" {
    rest_api_id = aws_api_gateway_rest_api.lts_api.id
    resource_id = aws_api_gateway_resource.lts_api_proxy.id
    http_method = aws_api_gateway_method.lts_api_proxy_method.http_method

    type = "HTTP_PROXY"
    integration_http_method = "GET"

    uri = "http://${aws_lb.lts_alb.dns_name}/{proxy}"

    request_parameters = {
        "integration.request.path.proxy" = "method.request.path.proxy"
    }
}

resource "aws_api_gateway_deployment" "lts_api_deployment" {
    rest_api_id = aws_api_gateway_rest_api.lts_api.id

    triggers = {
        redployment = sha1(jsonencode([
            aws_api_gateway_resource.lts_api_proxy.id,
            aws_api_gateway_method.lts_api_proxy_method.id,
            aws_api_gateway_integration.lts_api_proxy_integration.id,

            aws_api_gateway_method.lts_api_root_get_method.id,
            aws_api_gateway_integration.lts_api_root_get_integration.id
        ]))
    }

    depends_on = [
        aws_api_gateway_integration.lts_api_proxy_integration,
        aws_api_gateway_integration.lts_api_root_get_integration
    ]

    lifecycle {
        create_before_destroy = true
    }
}

resource "aws_api_gateway_stage" "lts_api_stage" {
    deployment_id = aws_api_gateway_deployment.lts_api_deployment.id
    rest_api_id = aws_api_gateway_rest_api.lts_api.id

    stage_name = "v1"
}

# 나중에 outputs.tf로 분리 
output "lts_api_gateway_url" {
    description = "The URL for the LTS service (via CloudFront)"
    value = "https://${aws_cloudfront_distribution.lts_cdn.domain_name}"
}

resource "aws_wafv2_web_acl" "lts_waf_acl" {
  name  = "lts-waf-acl"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 1

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"
        
        rule_action_override {
          name = "NoUserAgent_HEADER"
          action_to_use {
            count {}
          }
        }
      }
    }

    override_action {
      none {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "lts-waf-common-rules"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "lts-waf"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "lts-waf-acl"
  }
}

resource "aws_wafv2_web_acl" "lts_waf_acl_cloudfront" {
  provider = aws.us-east-1
  name  = "lts-waf-acl-cloudfront"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  rule {
    name     = "AWS-AWSManagedRulesCommonRuleSet"
    priority = 1

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        rule_action_override {
          name = "NoUserAgent_HEADER"
          action_to_use {
            count {}
          }
        }
      }
    }
    
    override_action {
      none {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "lts-waf-common-cf"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "lts-waf-cf"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "lts-waf-acl-cloudfront"
  }
}

resource "aws_cloudfront_distribution" "lts_cdn" {

    origin {
        domain_name = split("/", replace(aws_api_gateway_stage.lts_api_stage.invoke_url, "https://", ""))[0]

        # origin_path = "/${aws_api_gateway_stage.lts_api_stage.stage_name}"
        origin_path = ""

        origin_id = "api-gateway-origin"

        custom_origin_config {
            http_port = 80
            https_port = 443
            origin_protocol_policy = "https-only"
            origin_ssl_protocols = ["TLSv1.2"]
        }
    }
    
    enabled = true
    is_ipv6_enabled = true
    # default_root_object = "index.html"

    default_cache_behavior {
        allowed_methods = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
        cached_methods = ["GET", "HEAD"]
        target_origin_id = "api-gateway-origin"

        viewer_protocol_policy = "redirect-to-https"
        
        cache_policy_id = data.aws_cloudfront_cache_policy.caching_disabled.id
        
        origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    }

    web_acl_id = aws_wafv2_web_acl.lts_waf_acl_cloudfront.arn

    restrictions {
        geo_restriction {
            restriction_type = "none"
        }
    }

    viewer_certificate {
        cloudfront_default_certificate = true
    }

    depends_on = [
        aws_wafv2_web_acl.lts_waf_acl_cloudfront,
        aws_api_gateway_stage.lts_api_stage
    ]
}

resource "aws_cognito_user_pool" "lts_user_pool" {
        name = "lts-user-pool"

    password_policy {
        minimum_length    = 8
        require_lowercase = true
        require_numbers   = true
        require_symbols   = true
        require_uppercase = true
    }

    alias_attributes = ["email"]
    auto_verified_attributes = ["email"]

    tags = {
        Name = "lts-user-pool"
    }
}

resource "aws_cognito_user_pool_client" "lts_app_client" {
    name = "lts-api-client"
    user_pool_id = aws_cognito_user_pool.lts_user_pool.id

    explicit_auth_flows = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

    generate_secret = false
}

resource "aws_api_gateway_authorizer" "lts_cognito_auth" {
    name = "lts-cognito-authorizer"
    rest_api_id = aws_api_gateway_rest_api.lts_api.id
    type = "COGNITO_USER_POOLS"
    provider_arns = [aws_cognito_user_pool.lts_user_pool.arn]

    identity_source = "method.request.header.Authorization"
}

resource "aws_elasticache_subnet_group" "lts_cache_subnet_group" {
    name = "lts-cache-subnet-group"
    subnet_ids = [
        aws_subnet.lts_private_subnet.id,
        aws_subnet.lts_private_subnet_2a.id
    ]

    tags = {
        Name = "lts-cache-subnet-group"
    }
}

resource "aws_security_group" "lts_cache_sg" {
    name = "lts-cache-sg"
    description = "Allow Redis traffic from App SG"
    vpc_id = aws_vpc.lts_vpc.id

    ingress {
        description = "Redis from App Server"
        from_port = 6379
        to_port = 6379
        protocol = "tcp"
        security_groups = [aws_security_group.lts_app_sg.id]
    }

    egress {
        from_port = 0
        to_port = 0
        protocol = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }

    tags = {
        Name = "lts-cache-sg"
    }
}

resource "aws_elasticache_cluster" "lts_redis_cluster" {
    cluster_id = "lts-redis-cluster"
    engine = "redis"
    node_type = "cache.t3.micro"
    num_cache_nodes = 1
    parameter_group_name = "default.redis7"
    port = 6379

    subnet_group_name = aws_elasticache_subnet_group.lts_cache_subnet_group.name
    security_group_ids = [aws_security_group.lts_cache_sg.id]

    tags = {
        Name = "lts-redis-cluster"
    }
}

resource "aws_security_group" "lts_jenkins_sg" {
    name = "lts-jenkins-sg"
    description = "Allow SSH from Bastion and HTTP from specific IP"
    vpc_id = aws_vpc.lts_vpc.id

    ingress {
        description = "SSH from Bastion"
        from_port = 22
        to_port = 22
        protocol = "tcp"
        security_groups = [aws_security_group.lts_bastion_sg.id]
    }

    ingress {
    description     = "Jenkins Web UI from Bastion (Tunneling)"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.lts_bastion_sg.id]
    }

    ingress {
        description = "Jenkins Web UI from MY ip"
        from_port = 8080
        to_port = 8080
        protocol = "tcp"
        cidr_blocks = ["118.218.200.0/24"]
    }

    egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }


    tags = {
        Name = "lts-jenkins-sg"
    }
}

resource "aws_instance" "lts_jenkins_server" {
  ami                    = data.aws_ami.amazon_linux.id  # 이미 정의된 data source 사용
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.lts_private_subnet_2a.id
  vpc_security_group_ids = [aws_security_group.lts_jenkins_sg.id]
  key_name               = "lts-key-pair"
  
  iam_instance_profile   = aws_iam_instance_profile.lts_jenkins_profile.name  # 추가 권한 필요

  user_data = file("${path.module}/jenkins-userdata.sh")
  
  lifecycle {
    ignore_changes = [
      user_data
    ]
  }

  tags = {
    Name = "lts-jenkins-server"
  }
}

# Jenkins 인스턴스를 위한 IAM role (ECR, ECS 접근 필요)
resource "aws_iam_role" "lts_jenkins_role" {
  name = "lts-jenkins-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_instance_profile" "lts_jenkins_profile" {
  name = "lts-jenkins-profile"
  role = aws_iam_role.lts_jenkins_role.name
}

resource "aws_iam_role_policy_attachment" "jenkins_ecr_policy" {
  role       = aws_iam_role.lts_jenkins_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser"
}

resource "aws_iam_role_policy_attachment" "jenkins_ecs_policy" {
  role       = aws_iam_role.lts_jenkins_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonECS_FullAccess"
}

resource "aws_iam_role_policy_attachment" "jenkins_admin_policy" {
  role       = aws_iam_role.lts_jenkins_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"

  depends_on = [aws_iam_role.lts_jenkins_role]
}


# resource "aws_secretsmanager_secret" "lts_django_secret_key" {
#     name = "lts/django/secretkey"
#     description = "Django SECRET_KEY for LTS system"
#     recovery_window_in_days = 0
# }

# resource "aws_secretsmanager_secret_version" "lts_django_secret_key_version" {
#     secret_id = aws_secretsmanager_secret.lts_django_secret_key.id
#     secret_string = "django-insecure-dummy-key-for-lts-project"
# }

resource "aws_iam_policy" "lts_ecs_task_exec_secrets_policy" {
    name = "lts-ecs-task-exec-secrets-policy"
    description = "Allow ECS Task to read specific secrets"
    
    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
            {
                Effect   = "Allow"
                Action   = ["secretsmanager:GetSecretValue"]
                Resource = [
                    aws_secretsmanager_secret.lts_db_password_secret.arn,
                    # aws_secretsmanager_secret.lts_django_secret_key.arn
                ]
            }
        ]
    }) 
}

resource "aws_iam_role_policy_attachment" "ecs_secrets_attachment" {
  role       = aws_iam_role.lts_ecs_task_execution_role.name
  policy_arn = aws_iam_policy.lts_ecs_task_exec_secrets_policy.arn
}
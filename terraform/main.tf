terraform {
  required_providers {
    aws = {
        source = "hashicorp/aws"
        version = "~> 5.0"
    }
  }
}

provider "aws" {
    region = "ap-northeast-2"
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

    username = "admin"
    password  = "Password1234!"

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
            image = "nginxdemos/hello"
            essential = true
            portMappings = [
                {
                    containerPort = 80
                    hostPort = 80
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
    }

    configuration = jsonencode({
        Version = 1.0
        CrawlerOutput = {
            Partitions = { AddOrUpdateBehavior = "InheritFromTable"}
        }
        Grouping = {
            TableLevelConfiguration = 7
        }
    })

    schema_change_policy {
        update_behavior = "UPDATE_IN_DATABASE"
        delete_behavior = "LOG"
    }

    depends_on = [aws_iam_role_policy_attachment.lts_glue_policy_attachment]
}

resource "aws_glue_job" "lts_etl_job" {
    name = "lts-traffic-etl-job"
    role_arn = aws_iam_role.lts_glue_role.arn

    glue_version = "5.0"

    number_of_workers = 2
    worker_type = "G.1X"

    command {
        name = "glueetl"
        script_location = "s3://${aws_s3_bucket.lts_data_lake.id}/glue-scripts/lts_etl_script.py"
        python_version = "3"
    }

    default_arguments = {
        "--TempDir" = "s3://${aws_s3_bucket.lts_data_lake.id}/glue-temp/"
        "--job-bookmark-option" = "job-bookmark-enable"
    }

    depends_on = [aws_iam_role_policy_attachment.lts_glue_policy_attachment]
}


resource "aws_s3_object" "lts_glue_script_placeholer" {
    bucket = aws_s3_bucket.lts_data_lake.id
    key = "glue-scripts/lts_etl_script.py"
    content = <<-EOF
    import sys
    from awsglue.transforms import *
    from awsglue.utils import getResolvedOptions
    from pyspark.context import SparkContext
    from awsglue.context import GlueContext
    from awsglue.job import Job

    args = getResolvedOptions(sys.argv, ['JOB_NAME'])

    sc = SparkContext()
    glueContext = GlueContext(sc)
    spark = glueContext.spark_session
    job = Job(glueContext)
    job.init(args['JOB_NAME'], args)

    print("Placeholder job finished.")

    job.commit()
    EOF
}

# 나중에 확인
resource "aws_iam_policy" "lts_glue_s3_read_policy" {
  name        = "lts-glue-s3-read-policy"
  description = "Allow Glue role to read from the S3 data lake bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = [
          "s3:GetObject", # 객체 읽기
          "s3:ListBucket" # 버킷 내용물 보기 (크롤러에 필요)
        ]
        # 데이터 레이크 버킷 "안의 모든 것(*)"에 대한 권한 부여
        Resource = [
          aws_s3_bucket.lts_data_lake.arn,        # 버킷 자체 (ListBucket용)
          "${aws_s3_bucket.lts_data_lake.arn}/*"  # 버킷 안의 모든 객체 (GetObject용)
        ]
      }
    ]
  })
}

# --- 7. (신규) 새 S3 읽기 정책을 기존 Glue 역할에 연결 ---
resource "aws_iam_role_policy_attachment" "lts_glue_s3_read_attachment" {
  # (lts_glue_policy_attachment와 중복되지 않는 고유한 이름)
  role       = aws_iam_role.lts_glue_role.name
  policy_arn = aws_iam_policy.lts_glue_s3_read_policy.arn
}
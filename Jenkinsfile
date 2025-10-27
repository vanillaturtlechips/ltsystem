pipeline {
    agent any 
    environment {
        AWS_REGION = 'ap-northeast-2'
        TF_DIR     = 'terraform' 

        AWS_ACCOUNT_ID = '820313036770'
        ECR_REPO_NAME  = 'lts-app-repo'
        IMAGE_TAG      = "latest"
    }
    stages {
        stage('Checkout') {
            steps {
                echo "Checking out source code from Git..."
                checkout scm
            }
        }

        stage('Build & Push to ECR') {
            steps {
                echo "Building and pushing Docker image..."
                sh "aws ecr get-login-password --region ${AWS_REGION} | docker login --username AWS --password-stdin ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

                sh "cd backend && docker build --no-cache -t ${ECR_REPO_NAME}:${IMAGE_TAG} ."

                sh "docker tag ${ECR_REPO_NAME}:${IMAGE_TAG} ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}:${IMAGE_TAG}"

                sh "docker push ${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO_NAME}:${IMAGE_TAG}"
            }

        }

        
        stage('Terraform Init') {
            steps {
               
                echo "Running Terraform Init in ${TF_DIR}..."
                sh "cd ${TF_DIR} && terraform init"
            }
        }

        
        stage('Terraform Plan') {
            steps {
                echo "Running Terraform Plan..."
                sh "cd ${TF_DIR} && terraform plan -out=tfplan"
            }
        }

        
        stage('Approve Apply') {
            steps {
                
                echo "Waiting for manual approval to apply changes..."
                input 'Terraform Apply?'
            }
        }

        
        stage('Terraform Apply') {
            steps {
                
                echo "Running Terraform Apply..."
                sh "cd ${TF_DIR} && terraform apply -auto-approve tfplan"
            }
        }

        stage('Force ECS Deployment') {
                steps {
                    echo "Forcing new deployment on ECS service..."
                    sh "aws ecs update-service --cluster lts-cluster \
                        --service lts_app_service \
                        --force-new-deployment \
                        --region ${AWS_REGION}"
             }
         }
    }
} 
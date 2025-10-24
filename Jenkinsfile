pipeline {
    
    agent any 

    
    environment {
        AWS_REGION = 'ap-northeast-2'
        TF_DIR     = 'terraform' 
    }

    
    stages {
        
      
        stage('Checkout') {
            steps {
                echo "Checking out source code from Git..."
                checkout scm
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
                // 인프라 변경 계획을 생성하고 tfplan 파일로 저장
                echo "Running Terraform Plan..."
                sh "cd ${TF_DIR} && terraform plan -out=tfplan"
            }
        }

        
        stage('Approve Apply') {
            steps {
                
                echo "Waiting for manual approval to apply changes..."
                input 'Terraform Apply를 실행할까요?'
            }
        }

        
        stage('Terraform Apply') {
            steps {
                
                echo "Running Terraform Apply..."
                sh "cd ${TF_DIR} && terraform apply -auto-approve tfplan"
            }
        }
    } 

} 
pipeline {
    agent any

    environment {
        AWS_REGION = 'ap-northeast-2'
        TF_DIR = 'terraform'
    }


    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
    }

    stage('Terraform Init') {
        steps {
            sh "cd ${TF_DIR} && terraform init"
        }
    }

    stage('Terraform Plan') {
        steps {
            sh "cd ${TF_DIR} && terraform plan -out=tfplan"
        }
    }

    stage('Approve Apply') {
        steps {
            input 'Terraform Apply OK?'
        }
    }

    stage('Terraform Apply') {
        steps {
            sh "cd ${TF_DIR} && terraform apply -auto-approve tfplan"
        }
    }


}
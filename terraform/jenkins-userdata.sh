#!/bin/bash
set -e
exec > >(tee /var/log/user-data.log)
exec 2>&1

echo "========== Starting Jenkins Installation =========="

echo "ip_resolve=4" | sudo tee /etc/yum/vars/ip_resolve

# 시스템 업데이트
sudo yum update -y

# Java 11 설치
# sudo amazon-linux-extras install java-openjdk11 -y
sudo yum install -y java-17-amazon-corretto-devel
java -version

# Jenkins 저장소 추가 (최신 방식)
sudo wget -O /etc/yum.repos.d/jenkins.repo \
    https://pkg.jenkins.io/redhat-stable/jenkins.repo
sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io-2023.key

# Jenkins 설치
sudo yum install jenkins -y

# Jenkins 서비스 시작
sudo systemctl daemon-reload
sudo systemctl start jenkins
sudo systemctl enable jenkins

# 상태 확인
sudo systemctl status jenkins --no-pager

# Git 설치
sudo yum install -y git

# Docker 설치 (Jenkins에서 빌드에 필요)
sudo yum install -y docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker jenkins
sudo usermod -aG docker ec2-user

# AWS CLI 업데이트
sudo yum install -y aws-cli

# Terraform 설치
sudo yum install -y yum-utils
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
sudo yum install -y terraform

# Jenkins 초기 비밀번호 확인 가능하도록 권한 설정
sudo chmod 644 /var/lib/jenkins/secrets/initialAdminPassword

# 설치 완료 표시
echo "========== Jenkins Installation Completed =========="
echo "Initial Admin Password:"
sudo cat /var/lib/jenkins/secrets/initialAdminPassword 2>/dev/null || echo "Password file not ready yet"

echo "User data completed successfully" > /tmp/userdata-success.txt
date >> /tmp/userdata-success.txt
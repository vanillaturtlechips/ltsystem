terraform {
    backend "s3" {
        bucket = "lts-terraform-state-bucket-20251024"

        key = "lts-infra/terraform.tfstate"

        region = "ap-northeast-2"

        dynamodb_table = "lts-terraform-lock-table"

        encrypt = true
        
    }
}


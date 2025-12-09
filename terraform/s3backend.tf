terraform {
  backend "s3" {
    bucket = "my-tf-state-file-bucket-001"
    key    = "state/terraform.tfstate"
    region = "ap-south-1"
  }
}

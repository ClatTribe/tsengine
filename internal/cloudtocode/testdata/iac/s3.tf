resource "aws_s3_bucket" "assets" {
  bucket = "acme-prod-assets"

  tags = {
    Name = "acme-prod-assets"
    Env  = "prod"
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = var.logs_bucket_name
}

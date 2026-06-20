resource "aws_security_group" "web" {
  name        = "acme-web-sg"
  description = "web tier"
}

resource "aws_instance" "acme_app_server" {
  ami           = "ami-0abc123"
  instance_type = "t3.micro"
}

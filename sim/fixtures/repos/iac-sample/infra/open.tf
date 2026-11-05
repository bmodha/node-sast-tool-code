resource "aws_security_group" "wide" {
  name = "wide"
  ingress {
    description = "remote admin"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

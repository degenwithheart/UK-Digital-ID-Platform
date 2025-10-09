terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-2"
}

resource "aws_instance" "digital_id_server" {
  ami           = "ami-0c55b159cbfafe1d0"  # Ubuntu
  instance_type = "t2.micro"

  tags = {
    Name = "UK Digital ID Server"
  }
}
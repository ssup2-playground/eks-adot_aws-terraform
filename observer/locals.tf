locals {
  name = "ts-eks-adot"

  region   = "ap-northeast-2"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)

  vpc_observer_cidr = "10.0.0.0/16"
  vpc_workload_cidr = "10.10.0.0/16"

  s3_bucket_log  = "ts-eks-adot-ob-log"
  s3_dir_loki    = "loki"
}

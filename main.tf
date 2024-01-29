## Provider
provider "aws" {
  region = local.region
}

provider "aws" {
  alias  = "ecr"
  region = "us-east-1"
}

provider "kubernetes" {
  alias = "observer"

  host                   = module.eks_observer.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_observer.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks_observer.cluster_name]
  }
}

provider "kubernetes" {
  alias = "workload"

  host                   = module.eks_workload.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_workload.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks_workload.cluster_name]
  }
}

provider "helm" {
  alias = "observer"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_observer.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_observer.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_observer.cluster_name]
    }
  }
}

provider "helm" {
  alias = "workload"

  # to avoid issue : https://github.com/hashicorp/terraform-provider-helm/issues/630#issuecomment-996682323
  repository_config_path = "${path.module}/.helm/repositories.yaml" 
  repository_cache       = "${path.module}/.helm"

  kubernetes {
    host                   = module.eks_workload.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks_workload.cluster_certificate_authority_data)

    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--cluster-name", module.eks_workload.cluster_name]
    }
  }
}

provider "kubectl" {
  alias = "observer"

  apply_retry_count      = 5
  host                   = module.eks_observer.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_observer.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks_observer.cluster_name]
  }
}

provider "kubectl" {
  alias = "workload"

  apply_retry_count      = 5
  host                   = module.eks_workload.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_workload.cluster_certificate_authority_data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.eks_workload.cluster_name]
  }
}

provider "opensearch" {
  url         = aws_opensearch_domain.opensearch.endpoint
  aws_region  = local.region
  healthcheck = false
}

## Data
data "aws_availability_zones" "available" {}

data "aws_caller_identity" "current" {}

data "aws_ecrpublic_authorization_token" "token" {
  provider = aws.ecr
}

## CloudWatch Log Group
resource "aws_cloudwatch_log_group" "onebyone" {
  name = format("%s-onebyone", local.name)
}

resource "aws_cloudwatch_log_group" "atonce" {
  name = format("%s-atonce", local.name)
}

## AMP
module "prometheus" {
  source = "terraform-aws-modules/managed-service-prometheus/aws"

  workspace_alias = format("%s-amp-onebyone", local.name)
}

## VPC
module "vpc_observer" {
  source = "terraform-aws-modules/vpc/aws"

  name = format("%s-ob-vpc", local.name)

  cidr             = local.vpc_observer_cidr
  azs              = local.azs
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_observer_cidr, 4, k)]
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_observer_cidr, 4, k + 4)]

  enable_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  manage_default_network_acl    = true
  manage_default_route_table    = true
  manage_default_security_group = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1 # for AWS Load Balancer Controller
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1                               # for AWS Load Balancer Controller
    "karpenter.sh/discovery"          = format("%s-ob-eks", local.name) # for Karpenter
  }
}

module "vpc_workload" {
  source = "terraform-aws-modules/vpc/aws"

  name = format("%s-work-vpc", local.name)

  cidr             = local.vpc_workload_cidr
  azs              = local.azs
  public_subnets   = [for k, v in local.azs : cidrsubnet(local.vpc_workload_cidr, 4, k)]
  private_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_workload_cidr, 4, k + 4)]

  enable_nat_gateway   = true
  enable_dns_hostnames = true
  enable_dns_support   = true

  manage_default_network_acl    = true
  manage_default_route_table    = true
  manage_default_security_group = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1 # for AWS Load Balancer Controller
  }

  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1                                 # for AWS Load Balancer Controller
    "karpenter.sh/discovery"          = format("%s-work-eks", local.name) # for Karpenter
  }
}

module "tgw" {
  source  = "terraform-aws-modules/transit-gateway/aws"

  name = format("%s-tgw", local.name)

  share_tgw                              = false
  enable_dns_support                     = true
  enable_default_route_table_propagation = true
  enable_default_route_table_association = true

  vpc_attachments = {
    vpc_observer = {
      vpc_id     = module.vpc_observer.vpc_id
      subnet_ids = module.vpc_observer.private_subnets
    }

    vpc_workload = {
      vpc_id     = module.vpc_workload.vpc_id
      subnet_ids = module.vpc_workload.private_subnets
    }
  }
}

## EKS Observer
module "eks_observer" {
  providers = {
    kubernetes = kubernetes.observer
  }

  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-ob-eks", local.name)
  cluster_version = "1.28"

  vpc_id                          = module.vpc_observer.vpc_id
  subnet_ids                      = module.vpc_observer.private_subnets
  cluster_endpoint_public_access  = true

  manage_aws_auth_configmap = true

  ## Addons
  cluster_addons = {
    coredns = {
      addon_version = "v1.10.1-eksbuild.5"
      configuration_values = file("${path.module}/eks-addon-configs/coredns.json")
    }
    vpc-cni = {
      addon_version = "v1.14.1-eksbuild.1"
    }
    kube-proxy = {
      addon_version = "v1.28.1-eksbuild.1"
    }
    aws-ebs-csi-driver = {
      addon_version = "v1.25.0-eksbuild.1"
      service_account_role_arn = module.irsa_observer_ebs_csi_plugin.iam_role_arn
      configuration_values = file("${path.module}/eks-addon-configs/ebs-csi.json")
    }
    adot = {
      addon_version = "v0.90.0-eksbuild.1"
      configuration_values = file("${path.module}/eks-addon-configs/adot.json")
    }
  }

  ## Fargate
  fargate_profiles = {
    karpenter = {
      selectors = [
        { namespace = "karpenter" }
      ]
    }
  }

  ## Node Security Group
  node_security_group_tags = {
    "karpenter.sh/discovery" = format("%s-ob-eks", local.name) # for Karpenter
  }
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
  }

  aws_auth_roles = [
    {
      ## for Karpenter
      rolearn  = module.karpenter_observer.role_arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups = [
        "system:bootstrappers",
        "system:nodes",
      ]
    }
  ]
}

module "irsa_observer_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-observer-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

## EKS Observer / Karpenter
module "karpenter_observer" {
  source = "terraform-aws-modules/eks/aws//modules/karpenter"

  cluster_name           = module.eks_observer.cluster_name
  irsa_oidc_provider_arn = module.eks_observer.oidc_provider_arn

	enable_karpenter_instance_profile_creation = true

  iam_role_additional_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }
}

resource "helm_release" "observer_karpenter" {
  provider = helm.observer  

  namespace        = "karpenter"
  create_namespace = true

  name       = "karpenter"
  chart      = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  version    = "v0.32.5"

  set {
    name  = "settings.aws.clusterName"
    value = module.eks_observer.cluster_name
  }
  set {
    name  = "settings.aws.clusterEndpoint"
    value = module.eks_observer.cluster_endpoint
  }
  set {
    name  = "settings.aws.interruptionQueueName"
    value = module.karpenter_observer.queue_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.karpenter_observer.irsa_arn
  }

  depends_on = [
    module.karpenter_observer
  ]
}

resource "kubectl_manifest" "observer_karpenter_nodepool_core" {
  provider = kubectl.observer

  yaml_body = file("${path.module}/manifests/karpenter-nodepool-core.yaml")

  depends_on = [
    helm_release.observer_karpenter
  ]
}

resource "kubectl_manifest" "observer_karpenter_nodepool_default" {
  provider = kubectl.observer

  yaml_body = file("${path.module}/manifests/karpenter-nodepool-default.yaml")

  depends_on = [
    helm_release.observer_karpenter
  ]
}

resource "kubectl_manifest" "observer_karpenter_ec2nodeclass_default" {
  provider = kubectl.observer

  yaml_body = templatefile("${path.module}/manifests/karpenter-nodeclass-default.yaml", 
    { 
      cluster_name = module.eks_observer.cluster_name
      ec2_role_name = module.karpenter_observer.role_name
    }
  )

  depends_on = [
    helm_release.observer_karpenter
  ]
}

## EKS Observer / Cert Manager
resource "helm_release" "observer_cert_manager" {
  provider = helm.observer  

  create_namespace = true
  namespace  = "cert-manager"

  name       = "cert-manager"
  chart      = "cert-manager"
  repository = "https://charts.jetstack.io"
  version    = "v1.13.3"
 
  values = [
    file("${path.module}/helm-values/cert-manager.yaml")
  ]
  set {
    name  = "clusterName"
    value = module.eks_observer.cluster_name
  }

  depends_on = [
    helm_release.observer_karpenter
  ]
}

## EKS Observer / Load Balancer Controller
module "irsa_observer_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-observer-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa", "kube-system:ebs-csi-node-sa"]
    }
  }
}

resource "helm_release" "observer_aws_load_balancer_controller" {
  provider = helm.observer  

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"
 
  values = [
    file("${path.module}/helm-values/aws-load-balancer-controller.yaml")
  ]

  set {
    name  = "clusterName"
    value = module.eks_observer.cluster_name
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_observer_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_observer_load_balancer_controller,
		helm_release.observer_karpenter
  ]
}

## EKS Observer / Loki
resource "helm_release" "observer_loki" {
  provider = helm.observer  

  namespace        = "monitoring"
  create_namespace = true

  name       = "loki"
  chart      = "loki"
  repository = "https://grafana.github.io/helm-charts"
  version    = "v5.38.0"
 
  values = [
    file("${path.module}/helm-values/loki.yaml")
  ]

  depends_on = [
    helm_release.observer_karpenter
  ]
}

## EKS Observer / Tempo
resource "helm_release" "observer_tempo" {
  provider = helm.observer  

  namespace        = "monitoring"
  create_namespace = true

  name       = "tempo"
  chart      = "tempo"
  repository = "https://grafana.github.io/helm-charts"
  version    = "v1.7.1"
 
  values = [
    file("${path.module}/helm-values/tempo.yaml")
  ]

  depends_on = [
    helm_release.observer_karpenter
  ]
}

## EKS Observer / Grafana 
resource "helm_release" "observer_grafana" {
  provider = helm.observer  

  namespace        = "monitoring"
  create_namespace = true

  name       = "grafana"
  chart      = "grafana"
  repository = "https://grafana.github.io/helm-charts"
  version    = "v7.0.8"
 
  values = [
    file("${path.module}/helm-values/grafana.yaml")
  ]

  depends_on = [
    helm_release.observer_karpenter
  ]
}

## EKS Workload
module "eks_workload" {
  providers = {
    kubernetes = kubernetes.workload
  }

  source = "terraform-aws-modules/eks/aws"

  cluster_name = format("%s-work-eks", local.name)
  cluster_version = "1.28"

  vpc_id                          = module.vpc_workload.vpc_id
  subnet_ids                      = module.vpc_workload.private_subnets
  cluster_endpoint_public_access  = true

  manage_aws_auth_configmap = true

  ## Addons
  cluster_addons = {
    coredns = {
      addon_version = "v1.10.1-eksbuild.5"
      configuration_values = file("${path.module}/eks-addon-configs/coredns.json")
    }
    vpc-cni = {
      addon_version = "v1.14.1-eksbuild.1"
    }
    kube-proxy = {
      addon_version = "v1.28.1-eksbuild.1"
    }
    aws-ebs-csi-driver = {
      addon_version = "v1.25.0-eksbuild.1"
      service_account_role_arn = module.irsa_workload_ebs_csi_plugin.iam_role_arn
      configuration_values = file("${path.module}/eks-addon-configs/ebs-csi.json")
    }
    adot = {
      addon_version = "v0.90.0-eksbuild.1"
      configuration_values = file("${path.module}/eks-addon-configs/adot.json")
    }
  }

  ## Fargate
  fargate_profiles = {
    karpenter = {
      selectors = [
        { namespace = "karpenter" }
      ]
    }
  }

  ## Node Security Group
  node_security_group_tags = {
    "karpenter.sh/discovery" = format("%s-work-eks", local.name) # for Karpenter
  }
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
  }

  aws_auth_roles = [
    {
      ## for Karpenter
      rolearn  = module.karpenter_workload.role_arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups = [
        "system:bootstrappers",
        "system:nodes",
      ]
    }
  ]
}

module "irsa_workload_ebs_csi_plugin" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name             = format("%s-irsa-worklaod-ebs-csi-plugin", local.name)
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_workload.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

## EKS Workload / Karpenter
module "karpenter_workload" {
  source = "terraform-aws-modules/eks/aws//modules/karpenter"

  cluster_name           = module.eks_workload.cluster_name
  irsa_oidc_provider_arn = module.eks_workload.oidc_provider_arn

	enable_karpenter_instance_profile_creation = true

  iam_role_additional_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }
}

resource "helm_release" "workload_karpenter" {
  provider = helm.workload 

  namespace        = "karpenter"
  create_namespace = true

  name       = "karpenter"
  chart      = "karpenter"
  repository = "oci://public.ecr.aws/karpenter"
  version    = "v0.32.5"

  set {
    name  = "settings.aws.clusterName"
    value = module.eks_workload.cluster_name
  }
  set {
    name  = "settings.aws.clusterEndpoint"
    value = module.eks_workload.cluster_endpoint
  }
  set {
    name  = "settings.aws.interruptionQueueName"
    value = module.karpenter_workload.queue_name
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.karpenter_workload.irsa_arn
  }

  depends_on = [
    module.karpenter_workload
  ]
}

resource "kubectl_manifest" "workload_karpenter_nodepool_core" {
  provider = kubectl.workload

  yaml_body = file("${path.module}/manifests/karpenter-nodepool-core.yaml")

  depends_on = [
    helm_release.workload_karpenter
  ]
}

resource "kubectl_manifest" "workload_karpenter_nodepool_default" {
  provider = kubectl.workload

  yaml_body = file("${path.module}/manifests/karpenter-nodepool-default.yaml")

  depends_on = [
    helm_release.workload_karpenter
  ]
}

resource "kubectl_manifest" "workload_karpenter_ec2nodeclass_default" {
  provider = kubectl.workload

  yaml_body = templatefile("${path.module}/manifests/karpenter-nodeclass-default.yaml", 
    { 
      cluster_name = module.eks_workload.cluster_name
      ec2_role_name = module.karpenter_workload.role_name
    }
  )

  depends_on = [
    helm_release.workload_karpenter
  ]
}

## EKS Workload / Cert Manager
resource "helm_release" "workload_cert_manager" {
  provider = helm.workload  

  create_namespace = true
  namespace  = "cert-manager"

  name       = "cert-manager"
  chart      = "cert-manager"
  repository = "https://charts.jetstack.io"
  version    = "v1.13.3"
 
  values = [
    file("${path.module}/helm-values/cert-manager.yaml")
  ]
  set {
    name  = "clusterName"
    value = module.eks_workload.cluster_name
  }

  depends_on = [
    helm_release.workload_karpenter
  ]
}

## EKS Workload / Load Balancer Controller
module "irsa_workload_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-workload-aws-load-balancer-controller", local.name)
  attach_load_balancer_controller_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_workload.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
}

resource "helm_release" "workload_aws_load_balancer_controller" {
  provider = helm.workload  

  namespace  = "kube-system"
  name       = "aws-load-balancer-controller"
  chart      = "aws-load-balancer-controller"
  repository = "https://aws.github.io/eks-charts"
  version    = "v1.6.2"
 
  values = [
    file("${path.module}/helm-values/aws-load-balancer-controller.yaml")
  ]

  set {
    name  = "clusterName"
    value = module.eks_workload.cluster_name
  }
  set {
    name  = "serviceAccount.name"
    value = "aws-load-balancer-controller"
  }
  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = module.irsa_workload_load_balancer_controller.iam_role_arn
  }

  depends_on = [
    module.irsa_workload_load_balancer_controller,
		helm_release.workload_karpenter
  ]
}

## OpenSearch
resource "aws_opensearch_domain" "opensearch" {
  domain_name    = format("%s-opensearch", local.name)
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type = "m5.xlarge.search"
  }

  advanced_security_options {
	  enabled                        = true
    internal_user_database_enabled = true
    master_user_options {
      master_user_name     = "admin"
      master_user_password = "Admin123!"
    }
  }

  encrypt_at_rest {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  node_to_node_encryption {
    enabled = true
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 20
  }
}

data "aws_iam_policy_document" "opensearch_policy" {
  statement {
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["es:*"]
    resources = ["${aws_opensearch_domain.opensearch.arn}/*"]

    condition {
		  test     = "IpAddress"
      variable = "aws:SourceIp"
      values   = ["127.0.0.1/32"]
    }
  }
}

resource "aws_opensearch_domain_policy" "opensearch_access_policy" {
  domain_name     = aws_opensearch_domain.opensearch.domain_name
  access_policies = data.aws_iam_policy_document.opensearch_policy.json
}

## OpenSearch / Injest
resource "aws_iam_role" "opensearch_injest" {
  name = format("%s-opensearch-injest", local.name)

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          Service = "osis-pipelines.amazonaws.com"
        }	
      },
    ]
  })

  inline_policy {
    name = "OpenSearchInjest"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect   = "Allow"
          Action   = ["es:DescribeDomain", "es:ESHttp*"]
          Resource = "*"
        },
      ]
    })
  }
}

resource "awscc_osis_pipeline" "metrics_onebyone" {
  pipeline_name = format("%s-mt-onebyone", local.name)
  min_units     = 1
  max_units     = 4

  pipeline_configuration_body = templatefile("${path.module}/osis-configs/metrics-onebyone.yaml", 
    { 
      region = local.region, 
      opensearch_endpoint = aws_opensearch_domain.opensearch.endpoint,
      sts_role_arn = aws_iam_role.opensearch_injest.arn
    }
  )

  depends_on = [
	  aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}

resource "awscc_osis_pipeline" "metrics_atonce" {
  pipeline_name = format("%s-mt-atonce", local.name)
  min_units     = 1
  max_units     = 4

  pipeline_configuration_body = templatefile("${path.module}/osis-configs/metrics-atonce.yaml", 
    { 
      region = local.region, 
      opensearch_endpoint = aws_opensearch_domain.opensearch.endpoint,
      sts_role_arn = aws_iam_role.opensearch_injest.arn
    }
  )

  depends_on = [
	  aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}

resource "awscc_osis_pipeline" "logs_onebyone" {
  pipeline_name = format("%s-logs-onebyone", local.name)
  min_units     = 1
  max_units     = 4

  pipeline_configuration_body = templatefile("${path.module}/osis-configs/logs-onebyone.yaml", 
    { 
      region = local.region, 
      opensearch_endpoint = aws_opensearch_domain.opensearch.endpoint,
      sts_role_arn = aws_iam_role.opensearch_injest.arn
    }
  )

  depends_on = [
	  aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}

resource "awscc_osis_pipeline" "logs_atonce" {
  pipeline_name = format("%s-logs-atonce", local.name)
  min_units     = 1
  max_units     = 4

  pipeline_configuration_body = templatefile("${path.module}/osis-configs/logs-atonce.yaml", 
    { 
      region = local.region, 
      opensearch_endpoint = aws_opensearch_domain.opensearch.endpoint,
      sts_role_arn = aws_iam_role.opensearch_injest.arn
    }
  )

  depends_on = [
	  aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}

resource "awscc_osis_pipeline" "trace" {
  pipeline_name = format("%s-trace", local.name)
  min_units     = 1
  max_units     = 4

  pipeline_configuration_body = templatefile("${path.module}/osis-configs/trace.yaml", 
    { 
      region = local.region, 
      opensearch_endpoint = aws_opensearch_domain.opensearch.endpoint,
      sts_role_arn = aws_iam_role.opensearch_injest.arn
    }
  )

  depends_on = [
	  aws_opensearch_domain.opensearch,
    aws_iam_role.opensearch_injest
  ]
}

## ADOT Collector / CloudWatch Container Insight
module "irsa_observer_adot_collector_ci" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-observer-adot-collector-ci", local.name)
  attach_cloudwatch_observability_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["monitoring:adot-collector-ci"]
    }
  }

  depends_on = [
    module.eks_observer
  ]
}

data "kubectl_file_documents" "observer_adot_ci" {
  content = templatefile("${path.module}/manifests/adot-observer-ci.yaml",
    {
      ci_role_arn = module.irsa_observer_adot_collector_ci.iam_role_arn
    }
  )
}

resource "kubectl_manifest" "observer_adot_ci" {
  provider = kubectl.observer

  for_each = data.kubectl_file_documents.observer_adot_ci.manifests
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## ADOT Collector / CloudWatch Logs
module "irsa_observer_adot_collector_cl" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                              = format("%s-irsa-observer-adot-collector-cl", local.name)
  attach_cloudwatch_observability_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["monitoring:adot-collector-cl"]
    }
  }

  depends_on = [
    module.eks_observer
  ]
}

data "kubectl_file_documents" "observer_adot_cl" {
  content = templatefile("${path.module}/manifests/adot-observer-cl.yaml",
    {
      region         = local.region
      cl_role_arn    = module.irsa_observer_adot_collector_cl.iam_role_arn
      log_group_name = aws_cloudwatch_log_group.onebyone.name
    }
  )
}

resource "kubectl_manifest" "observer_adot_cl" {
  provider = kubectl.observer

  for_each = data.kubectl_file_documents.observer_adot_cl.manifests
  yaml_body = each.value

  depends_on = [
    module.eks_observer
  ]
}

## ADOT Collector / AMP
module "irsa_observer_adot_collector_amp" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"

  role_name                                       = format("%s-irsa-observer-adot-collector-amp", local.name)
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks_observer.oidc_provider_arn
      namespace_service_accounts = ["monitoring:adot-collector-amp"]
    }
  }

  depends_on = [
    module.eks_observer
  ]
}

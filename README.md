# eks-full_aws-terraform 

## Ops Cluster

* AWS access key, AWS secret key

```bash
$ kubectl create namespace monitoring
$ kubectl -n monitoring create secret generic aws-secret --from-literal=AWS_KEY_ACCESS=[access key] --from-literal=AWS_KEY_SECRET=[secret key]
```

## Dev Cluster

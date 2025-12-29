# Terraform Enterprise FDO Deployment on AWS using Podman and external services mode

This repository provides an automated way to deploy Terraform Enterprise (TFE) on AWS using:
- FDO (Flexible Deployment Options)
- Podman
- Active-active operational mode
- Terraform

This project automates the entire process, providing a repeatable, consistent, and reliable way to deploy TFE in minutes using Terraform.

## Prerequistes

This guide was executed on MacOS so it assumes the following:
- You have Git installed.
- AWS Credentials are configured.
- Terraform is installed (tested with Terraform 1.5.7)
- TFE license file


## Clone the repository
- Clone the Github repo
```
git clone https://github.com/mohamed-hashicorp/tfe-fdo-podman-es-si.git
```
- Change the directory
```
cd tfe-fdo-podman-es-si
```

## Configure your variables
- Rename the `terraform.tfvars.example`
```
cp terraform.tfvars.example terraform.tfvars
```
- Set the TFE image tag, license and encrytion password
```
tfe_image_tag = "v202503-1" 
tfe_license = "02MV4UU43BK5HGY...." 
tfe_encryption_password = "Mystrongpassword123" 
```

## Create Infrastructure
- Run Terraform init
```
terraform init
```

- Run Terraform apply
```
terraform apply
```

- Type yes if you prompted the following
```
Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: 
```


## Verify
- Check that TFE installation is accessible from your browser.
- Login to `https://server.mohamed-abdelbaset.sbx.hashidemos.io/`


## Delete Infrastructure
- When done, you can remove the resources with terraform destroy, type:
```
terraform destroy
```
- Type yes, when prompted:
```
    Do you really want to destroy all resources?
    Terraform will destroy all your managed infrastructure, as shown above.
    There is no undo. Only 'yes' will be accepted to confirm.
    Enter a value: 
```

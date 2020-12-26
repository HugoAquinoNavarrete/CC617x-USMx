# CC617x-USMx - Cloud Computing Security

Script on Terraform to use IaC concepts to automate the deploy BallotOnline security improvements and RDS using MySQL configuration

## 1. Configure AWS (this script runs on us-west-2 region)
Before execute this script, execute `aws configure` in order to enable
   - AWS Access Key ID
   - AWS Secret Access Key
   - Default region name 
   - Default output format (json,yaml,yaml-stream,text,table)

## 2. Generate a key pair rsa public/private
   ```bash 
   ssh-keygen
   ```
   The key name must be `cc617x-key-iac.pub`, save on the directory where you will run this script `<absolute_path>/cc617x-key-iac`, left empty `passphrase`

## 3. To connect through SSH to the VM (validate that in your Security Group you have enabled ingress permission to SSH - port TCP 22)
   ```bash
   ssh -v -l ec2-user -i cc617x-key-iac <public_ip_ec2_instance>
   ```

## 4. Script compatible with Terraform version v0.13.5, these are the steps to download and install
   ```bash
  wget https://releases.hashicorp.com/terraform/0.13.5/terraform_0.13.5_linux_amd64.zip
  unzip terraform_0.13.5_linux_amd64.zip
  sudo mv terraform /usr/local/bin/
  terraform --version 
   ```
## 5. The first that the script will be executed, this command will initialize Terraform `terraform init`

## 6. To execute the script type `terraform apply` when the following message appears, answer writing `yes`:
   ```bash
   Do you want to perform these actions?
     Terraform will perform the actions described above.
     Only 'yes' will be accepted to approve.

     Enter a value:
   ```

The script after beeing executed will generate a message like this:

   ```bash
   Apply complete! Resources: <amount> added, 0 changed, 0 destroyed.
   ```

## 7. To validate that the Load Balancer is responding, on the screen some Outputs variables will be displayed, find `alb_dns_name` and type:
   ```bash
   curl <load_balancer_name>
   ```

## 8. To eliminate the infrastructure created type `terraform destroy` when the following message appears, answer writing `yes`:
   ```bash
   Do you really want to destroy?
     Terraform will destroy all your managed infrastructure, as shown above.
     There is no undo. Only 'yes' will be accepted to confirm.

     Enter a value:
   ```

The script after beeing executed will generate a message like this:

   ```bash
   Destroy complete! Resources: <amount> destroyed.
   ```

## 9. Validate on AWS portal that the resources were eliminated (WAF, LoadBalancer, EC2, RDS)
EC2 instances must appear with `Terminated` state and some minutes later will disappear

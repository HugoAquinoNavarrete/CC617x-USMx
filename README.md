# CC617x-USMx - Cloud Computing Security

Script on Terraform to use IaC concepts to automate the deploy BallotOnline security improvements and RDS using MySQL configuration

-----

## 1. Configure AWS (this script runs on us-west-2 region)
Before execute this script, execute `aws configure` in order to enable
   - AWS Access Key ID
   - AWS Secret Access Key
   - Default region name 
   - Default output format (json,yaml,yaml-stream,text,table)

-----

## 2. Generate a key pair rsa public/private
   ```bash 
   ssh-keygen
   ```
   The key name must be `cc617x-key-iac.pub`, save on the directory where you will run this script `<absolute_path>/cc617x-key-iac`, left empty `passphrase`

-----

## 3. To connect through SSH to the VM (validate that in your Security Group you have enabled ingress permission to SSH - port TCP 22)
   ```bash
   ssh -v -l ec2-user -i cc617x-key-iac <public_ip_ec2_instance>
   ```

-----

## 4. Script compatible with Terraform version v0.13.5, these are the steps to download and install
   ```bash
  wget https://releases.hashicorp.com/terraform/0.13.5/terraform_0.13.5_linux_amd64.zip
  unzip terraform_0.13.5_linux_amd64.zip
  sudo mv terraform /usr/local/bin/
  terraform --version 
   ```

-----

## 5. The first that the script will be executed, this command will initialize Terraform `terraform init`

  ```bash
   Initializing the backend...

   Initializing provider plugins...
   - Using previously-installed hashicorp/aws v3.22.0

   The following providers do not have any version constraints in configuration,
   so the latest version was installed.

   To prevent automatic upgrades to new major versions that may contain breaking
   changes, we recommend adding version constraints in a required_providers block
   in your configuration, with the constraint strings suggested below.

   * hashicorp/aws: version = "~> 3.22.0"

   Terraform has been successfully initialized!

   You may now begin working with Terraform. Try running "terraform plan" to see
   any changes that are required for your infrastructure. All Terraform commands
   should now work.

   If you ever set or change modules or backend configuration for Terraform,
   rerun this command to reinitialize your working directory. If you forget, other
   commands will detect it and remind you to do so if necessary.

   ```

-----

## 6. To execute the script:

If only the e-mail where the notifications will be has to be defined, type `terraform apply -var "email=<email_address>"`

If in addition to the notifications the amount of default instances must be changed, type `terraform apply -var "minimum=<minimum_instances>" -var "maximum=<maximum_instances> -var "email=<email_address>"`

When the following message appears, answer writing `yes`:

   ```bash
   Do you want to perform these actions?
     Terraform will perform the actions described above.
     Only 'yes' will be accepted to approve.

     Enter a value:
   ```

The script will take some minutes to be executed, and after beeing executed, a message like this will be generated:

   ```bash
   Apply complete! Resources: <amount_resources_created> added, 0 changed, 0 destroyed.

   Outputs:

   alb_dns_name = <application_load_balancer_name>

   ```

-----

## 7. To validate that the Load Balancer is responding, on the screen some Outputs variables will be displayed, find `alb_dns_name` and type:
   ```bash
   curl <application_load_balancer_name>
   ```

-----

## 8. During the execution of the infrastructure deployment script, a notification to the e-mail will be sent with a subject `AWS Notification - Subscription Confirmation`, please confirm the subscription in order to receive the notification that will be generated when the thresholds will be exceeded:

-----

## 7. In order to test the differente WAF rules, the tool `hey` will be used to generate HTTP load to the Application Load Balancer instance recently created. 

In this site appears another OpenSource tools that can be used in further needs `https://awesomeopensource.com/project/denji/awesome-http-benchmark`

On CloudWatch a dashboard will be created that consolidate the metrics used in this project.

To test the requests handled by the Application Load Manager

   ```bash
   curl <load_balancer_name>
   ```

-----

## 10. To eliminate the infrastructure created type `terraform destroy` when the following message appears, answer writing `yes`:
   ```bash
   Do you really want to destroy?
     Terraform will destroy all your managed infrastructure, as shown above.
     There is no undo. Only 'yes' will be accepted to confirm.

     Enter a value:
   ```

The script after beeing executed will generate a message like this:

   ```bash
   Destroy complete! Resources: <amount_resources_deleted> destroyed.
   ```

-----

## 11. Validate on AWS portal that the resources were eliminated (WAF, LoadBalancer, EC2, RDS)
EC2 instances must appear with `Terminated` state and some minutes later will disappear

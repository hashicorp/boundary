## running ipv6-only enos tests without an ipv6 connection

1. create ipv6-enabled vpc
2. create ipv6-enabled subnet
3. create internet gateway and route
	- likely needs more detail
4. create t2-medium instance
	- attach the vpc
	- add public ipv4
	- add public ipv6
	- use at least 20gb storage
5. create a new policy and attach it to the ec2 instance
	```json
	{
		"Version": "2012-10-17",
		"Statement": [
			{
				"Sid": "VisualEditor0",
				"Effect": "Allow",
				"Action": [
					"ec2:DescribeImages",
					"ec2:DescribeInstanceTypeOfferings",
					"ec2:DescribeAvailabilityZones",
					"ec2:CreateVpc",
					"kms:CreateKey",
					"ec2:CreateTags",
					"kms:DescribeKey",
					"ec2:DescribeVpcs",
					"kms:ScheduleKeyDeletion",
					"kms:GetKeyPolicy",
					"kms:GetKeyRotationStatus",
					"kms:ListResourceTags",
					"kms:CreateAlias",
					"ec2:DeleteVpc",
					"ec2:ModifyVpcAttribute",
					"kms:ListAliases",
					"ec2:DescribeVpcAttribute",
					"kms:DeleteAlias",
					"ec2:CreateSubnet",
					"ec2:CreateInternetGateway",
					"ec2:CreateSecurityGroup",
					"ec2:DescribeSecurityGroups",
					"ec2:AttachInternetGateway",
					"ec2:DescribeSubnets",
					"ec2:DescribeNetworkInterfaces",
					"ec2:DeleteSubnet",
					"ec2:DeleteSecurityGroup",
					"ec2:RevokeSecurityGroupEgress",
					"ec2:ModifySubnetAttribute",
					"ec2:DetachInternetGateway",
					"ec2:AuthorizeSecurityGroupIngress",
					"ec2:DeleteInternetGateway",
					"ec2:AuthorizeSecurityGroupEgress",
					"ec2:DescribeInternetGateways",
					"ec2:DescribeRouteTables",
					"ec2:CreateRoute",
					"ec2:RevokeSecurityGroupIngress",
					"iam:CreateUser",
					"iam:DeleteUser",
					"iam:TagUser",
					"iam:GetUser",
					"iam:ListGroupsForUser",
					"iam:CreateAccessKey",
					"iam:DeleteAccessKey",
					"iam:PutUserPolicy",
					"iam:GetUserPolicy",
					"iam:DeleteUserPolicy",
					"ec2:DeleteRoute",
					"ec2:RunInstances",
					"ec2:DescribeInstances",
					"rds:CreateDBSubnetGroup",
					"iam:CreateRole",
					"elasticloadbalancing:DescribeTargetGroups",
					"ec2:TerminateInstances",
					"ec2:DescribeInstanceTypes",
					"rds:DescribeDBSubnetGroups",
					"iam:GetRole",
					"elasticloadbalancing:CreateTargetGroup",
					"elasticloadbalancing:DeleteTargetGroup",
					"rds:DeleteDBSubnetGroup",
					"iam:ListInstanceProfilesForRole",
					"iam:DeleteRole",
					"ec2:DescribeTags",
					"rds:ListTagsForResource",
					"iam:ListRolePolicies",
					"elasticloadbalancing:AddTags",
					"ec2:DescribeInstanceAttribute",
					"rds:CreateDBInstance",
					"iam:ListAttachedRolePolicies",
					"elasticloadbalancing:ModifyTargetGroupAttributes",
					"rds:DeleteDBInstance",
					"ec2:DescribeVolumes",
					"rds:AddTagsToResource",
					"iam:PutRolePolicy",
					"iam:DeleteRolePolicy",
					"iam:CreateInstanceProfile",
					"iam:DeleteInstanceProfile",
					"elasticloadbalancing:DescribeTargetGroupAttributes",
					"ec2:DescribeInstanceCreditSpecifications",
					"rds:DescribeDBInstances",
					"iam:GetRolePolicy",
					"iam:GetInstanceProfile",
					"elasticloadbalancing:DescribeTags",
					"iam:RemoveRoleFromInstanceProfile",
					"iam:AddRoleToInstanceProfile",
					"elasticloadbalancing:DescribeLoadBalancers",
					"elasticloadbalancing:RegisterTargets",
					"elasticloadbalancing:CreateLoadBalancer",
					"elasticloadbalancing:DeregisterTargets",
					"elasticloadbalancing:ModifyLoadBalancerAttributes",
					"elasticloadbalancing:DeleteLoadBalancer",
					"elasticloadbalancing:DescribeLoadBalancerAttributes",
					"elasticloadbalancing:CreateListener",
					"elasticloadbalancing:DescribeListeners",
					"elasticloadbalancing:DeleteListener",
					"ec2:AssociateRouteTable",
					"ec2:DisassociateRouteTable",
					"ec2:CreateIpam",
					"ec2:DeleteIpam",
					"ec2:ModifyIpam",
					"ec2:DescribeIpams",
					"ec2:CreateIpamPool",
					"ec2:DeleteIpamPool",
					"ec2:ModifyIpamPool",
					"ec2:DescribeIpamPools",
					"ec2:AllocateIpamPoolCidr",
					"ec2:ProvisionIpamPoolCidr",
					"s3:CreateBucket",
					"s3:DeleteBucket",
					"s3:ListBucket",
					"s3:ListAllMyBuckets",
					"s3:GetAccelerateConfiguration",
					"s3:PutAccelerateConfiguration",
					"s3:GetLifecycleConfiguration",
					"s3:PutLifecycleConfiguration",
					"s3:GetReplicationConfiguration",
					"s3:PutReplicationConfiguration",
					"s3:GetBucket*",
					"s3:PutBucket*",
					"s3:GetEncryptionConfiguration",
					"s3:PutEncryptionConfiguration",
					"ec2:AttachNetworkInterface",
					"ec2:DetachNetworkInterface",
					"iam:CreateServiceLinkedRole",
					"iam:DeleteServiceLinkedRole",
					"iam:PassRole"
				],
				"Resource": "*"
			}
		]
	}
	```
6. change sudo password
	- `sudo passwd ec2-user`
	- enter new password (doesn't need to be secure)
7. install git
	- `sudo yum install git`
8. install homebrew
	- https://brew.sh/
		- follow post-install instructions given by homebrew in the cli (install gcc and other utils)
9. install enos deps
	- https://github.com/hashicorp/boundary/blob/main/enos/README.md
		- you do **not** need to install doormat
		- you will need to create/add/use a github token on the ec2 instance
		- https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account
	- also install nvm and run `nvm install 20` and `nvm use 20`
		- https://github.com/nvm-sh/nvm?tab=readme-ov-file#installing-and-updating
10. you should now be able to run enos instances from the enos directory

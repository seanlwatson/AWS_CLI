Deploying a web application with AWS CLI
===

# Install AWS CLI

Install the AWS CLI, see [AWS CLI](https://aws.amazon.com/cli/) and [Installing the AWS Command Line Interface] 

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ sudo apt install awscli -y
</pre>

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws --version
aws-cli/1.14.44 Python/3.6.6 Linux/4.15.0-36-generic botocore/1.8.48
</pre>

[Access keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_CreateAccessKey) consist of an access key ID and secret access key, which are used to sign programmatic requests that you make to AWS. The `aws configure` command will prompt you for four pieces of information. AWS Access Key ID and AWS Secret Access Key are your programatic account credentials. Specify an AWS region and are the same names you see in the mgt. console. The default output can be either _json, text, or table_, where the default format is _json_.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws configure
AWS Access Key ID [None]: 
AWS Secret Access Key [None]: 
Default region name [None]: us-west-2
Default output format [None]: json
</pre>

Verify operation by listing all IAM users.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws iam list-users
{
    &quot;Users&quot;: [
        {
            &quot;Path&quot;: &quot;/&quot;,
            &quot;UserName&quot;: &quot;sean&quot;,
            &quot;UserId&quot;: &quot;AIDAJODWTO2Q2GNNXKUMA&quot;,
            &quot;Arn&quot;: &quot;arn:aws:iam::404297683117:user/sean&quot;,
            &quot;CreateDate&quot;: &quot;2018-05-08T00:38:00Z&quot;,
            &quot;PasswordLastUsed&quot;: &quot;2018-09-25T01:22:12Z&quot;
        }
    ]
}
</pre>

In order to launch a virtual server use the `aws ec2 run-instances` with the following parameters:
- AMI ID
- Instance type
- Security Group
- SSH key-pair

# AMI

An Amazon Machine Image (AMI) is a package that contains the OS and additional software required to start the system. 

1. Use the `aws ec2 describe-images` command along with filter options to only include the AMI wanted. In the filter use _x84_64_ bits version to match the architecture. The virtualization type will be _HVM_. There are two types of AMI virtualization: **Para-Virtual (PV)** and **Hardware Virtual Machine (HVM)**. The main difference between them is the boot process and how they take advantage of special hardware extensions like CPU, network, and storage for better performance. The _GP2_ is for General Purpose SSD (gp2), which is a type of EBS (Elastic Block Store) Volume.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 describe-images --filters &quot;Name=description,Values=Amazon Linux AMI * x86_64 HVM GP2&quot; --query &apos;Images[*].[CreationDate, Description, ImageId]&apos; --output text | sort -k 1 | tail
2018-01-08T18:43:49.000Z	Amazon Linux AMI 2017.09.1.20180108 x86_64 HVM GP2	ami-32cf7b4a
2018-01-10T18:59:11.000Z	Amazon Linux AMI 2017.09.1.20180108 x86_64 HVM GP2	ami-2a853252
2018-01-15T19:13:58.000Z	Amazon Linux AMI 2017.09.1.20180115 x86_64 HVM GP2	ami-f2d3638a
2018-01-18T23:11:52.000Z	Amazon Linux AMI 2017.09.1.20171120 x86_64 HVM GP2	ami-e6f84a9e
2018-03-07T06:59:59.000Z	Amazon Linux AMI 2017.09.1.20180307 x86_64 HVM GP2	ami-d874e0a0
2018-03-07T07:11:48.000Z	Amazon Linux AMI 2017.09.1-testlongids.20180307 x86_64 HVM GP2	ami-0163da89c9a854198
2018-04-13T00:32:56.000Z	Amazon Linux AMI 2018.03.0.20180412 x86_64 HVM GP2	ami-6b8cef13
2018-05-08T18:06:57.000Z	Amazon Linux AMI 2018.03.0.20180508 x86_64 HVM GP2	ami-e251209a
2018-06-22T22:27:00.000Z	Amazon Linux AMI 2018.03.0.20180622 x86_64 HVM GP2	ami-0ad99772
2018-08-11T02:29:45.000Z	Amazon Linux AMI 2018.03.0.20180811 x86_64 HVM GP2	ami-a0cfeed8
</pre>


> `--filter` allows you to filter the output based on the JSON data which represented in data name/value pairs.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 describe-images --filters &quot;Name=image-id,Values=ami-a0cfeed8&quot;
{
    &quot;Images&quot;: [
        {
            &quot;Architecture&quot;: &quot;x86_64&quot;,
            &quot;CreationDate&quot;: &quot;2018-08-11T02:29:45.000Z&quot;,
            &quot;ImageId&quot;: &quot;ami-a0cfeed8&quot;,
            &quot;ImageLocation&quot;: &quot;amazon/amzn-ami-hvm-2018.03.0.20180811-x86_64-gp2&quot;,
            &quot;ImageType&quot;: &quot;machine&quot;,
            &quot;Public&quot;: true,
            &quot;OwnerId&quot;: &quot;137112412989&quot;,
            &quot;State&quot;: &quot;available&quot;,
            &quot;BlockDeviceMappings&quot;: [
                {
                    &quot;DeviceName&quot;: &quot;/dev/xvda&quot;,
                    &quot;Ebs&quot;: {
                        &quot;Encrypted&quot;: false,
                        &quot;DeleteOnTermination&quot;: true,
                        &quot;SnapshotId&quot;: &quot;snap-0b9ac5da0147e5eb2&quot;,
                        &quot;VolumeSize&quot;: 8,
                        &quot;VolumeType&quot;: &quot;gp2&quot;
                    }
                }
            ],
            &quot;Description&quot;: &quot;Amazon Linux AMI 2018.03.0.20180811 x86_64 HVM GP2&quot;,
            &quot;EnaSupport&quot;: true,
            &quot;Hypervisor&quot;: &quot;xen&quot;,
            &quot;ImageOwnerAlias&quot;: &quot;amazon&quot;,
            &quot;Name&quot;: &quot;amzn-ami-hvm-2018.03.0.20180811-x86_64-gp2&quot;,
            &quot;RootDeviceName&quot;: &quot;/dev/xvda&quot;,
            &quot;RootDeviceType&quot;: &quot;ebs&quot;,
            &quot;SriovNetSupport&quot;: &quot;simple&quot;,
            &quot;VirtualizationType&quot;: &quot;hvm&quot;
        }
    ]
}</pre>


> `tail` is a command-line utility for outputting the last part of files given to it via standard input and writes results to standard output. By default tail returns the last ten lines of each file that it is given.

> `sort` is a command-line utility for sorting with the `-k 1` option sorts the data fields using the 1st column number (the newest being on the bottom).

> `--query` supplements commands to filter only information wanted and uses the JMESPath query language for JSON. The `Images[*]` uses an Index Expression, which is used to access elements in a list by indexing - in this case all Images. `.[CreationDate, Description, ImageId]` is part of a subexpression, which is a combination of two expressions separated by the `.` char. The brackets `[ ...]` is a MultiSelect List, which extracts a subset of elements separated by a `,` from a JSON hash. See [JMESPath](http://jmespath.org/tutorial.html) for more information.

# Instance type

**Instance type** comprise varying combinations of CPU, memory, storage, and networking capacity and each instance type includes one or more instance sizes.

The t2.micro includes the following:

| Model	| vCPU | CPU Credits / hour | Mem (GiB) | Storage |
|:-----:|:----:|:------------------:|:---------:|:-------:|
| t2.micro | 1 | 6 | 1 | EBS-Only |

# Security Group

**Security Groups** act as a virtual firewall (stateful) for your instance to control inbound and outbound traffic. The small web application will run on TCP/3000 and we want to support SSH TCP/22. Security Groups are tied to subnets within a Virtual Private Cloud (VPC). 

1. Run the following command to find the default VPC ID.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 describe-vpcs
{
    &quot;Vpcs&quot;: [
        {
            &quot;CidrBlock&quot;: &quot;172.31.0.0/16&quot;,
            &quot;DhcpOptionsId&quot;: &quot;dopt-b0dbadc9&quot;,
            &quot;State&quot;: &quot;available&quot;,
            &quot;VpcId&quot;: &quot;vpc-b3b5feca&quot;,
            &quot;InstanceTenancy&quot;: &quot;default&quot;,
            &quot;CidrBlockAssociationSet&quot;: [
                {
                    &quot;AssociationId&quot;: &quot;vpc-cidr-assoc-a7c0ddcc&quot;,
                    &quot;CidrBlock&quot;: &quot;172.31.0.0/16&quot;,
                    &quot;CidrBlockState&quot;: {
                        &quot;State&quot;: &quot;associated&quot;
                    }
                }
            ],
            &quot;IsDefault&quot;: true,
            &quot;Tags&quot;: [
                {
                    &quot;Key&quot;: &quot;Name&quot;,
                    &quot;Value&quot;: &quot;Default VPC&quot;
                }
            ]
        }
    ]
}
</pre>

2. Create a Security Group for the default VPC ID.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 create-security-group --group-name HelloWorld --description &quot;Hello World Demo&quot; --vpc-id vpc-b3b5feca
{
    &quot;GroupId&quot;: &quot;sg-0e2799ad580df135d&quot;
}
</pre>

3. By default Security Groups allow all outbound traffic from the instance but deny all inbound traffic. Open up SSH TCP/22 & TCP/3000 for inbound connectivity.

![](https://i.imgur.com/BVeSNGU.png)

![](https://i.imgur.com/GCTiUwf.png)

:::info
You can get your public IP address with the following command:

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ dig +short myip.opendns.com @resolver1.opendns.com
75.166.145.22</pre>

Or install curl and try this:

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ sudo apt install curl -y
</pre>

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ curl https://api.ipify.org
75.166.145.22</pre>
:::

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 authorize-security-group-ingress --group-name HelloWorld --protocol tcp --port 22 --cidr 75.166.145.22/32
</pre>

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 authorize-security-group-ingress --group-name HelloWorld --protocol tcp --port 3000 --cidr 75.166.145.22/32
</pre>

![](https://i.imgur.com/OxiAuJY.png)

4. Verify the Security Group.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 describe-security-groups --group-names HelloWorld --output table
&#45;---------------------------------------------------------------------------------------------
|                                   DescribeSecurityGroups                                   |
+--------------------------------------------------------------------------------------------+
<font color="#836B00">|</font>|                                      SecurityGroups                                      |<font color="#836B00">|</font>
<font color="#836B00">|</font>+------------------+------------------------+-------------+---------------+----------------+<font color="#836B00">|</font>
<font color="#836B00">|</font>|    Description   |        GroupId         |  GroupName  |    OwnerId    |     VpcId      |<font color="#836B00">|</font>
<font color="#836B00">|</font>+------------------+------------------------+-------------+---------------+----------------+<font color="#836B00">|</font>
<font color="#836B00">|</font>|  <font color="#729FCF"><b>Hello World Demo</b></font>|  <font color="#729FCF"><b>sg-0e2799ad580df135d</b></font>  |  <font color="#729FCF"><b>HelloWorld</b></font> |  <font color="#729FCF"><b>404297683117</b></font> |  <font color="#729FCF"><b>vpc-b3b5feca</b></font>  |<font color="#836B00">|</font>
<font color="#836B00">|</font>+------------------+------------------------+-------------+---------------+----------------+<font color="#836B00">|</font>
<font color="#836B00">||</font>|                                      IpPermissions                                     |<font color="#836B00">||</font>
<font color="#836B00">||</font>+----------------------------+----------------------------------+------------------------+<font color="#836B00">||</font>
<font color="#836B00">||</font>|          FromPort          |           IpProtocol             |        ToPort          |<font color="#836B00">||</font>
<font color="#836B00">||</font>+----------------------------+----------------------------------+------------------------+<font color="#836B00">||</font>
<font color="#836B00">||</font>|  <font color="#729FCF"><b>22</b></font>                        |  <font color="#729FCF"><b>tcp</b></font>                             |  <font color="#729FCF"><b>22</b></font>                    |<font color="#836B00">||</font>
<font color="#836B00">||</font>+----------------------------+----------------------------------+------------------------+<font color="#836B00">||</font>
<font color="#836B00">|||</font>|                                       IpRanges                                       |<font color="#836B00">|||</font>
<font color="#836B00">|||</font>+--------------------------------------------------------------------------------------+<font color="#836B00">|||</font>
<font color="#836B00">|||</font>|                                        CidrIp                                        |<font color="#836B00">|||</font>
<font color="#836B00">|||</font>+--------------------------------------------------------------------------------------+<font color="#836B00">|||</font>
<font color="#836B00">|||</font>|  <font color="#729FCF"><b>75.166.145.22/32</b></font>                                                                    |<font color="#836B00">|||</font>
<font color="#836B00">|||</font>+--------------------------------------------------------------------------------------+<font color="#836B00">|||</font>
<font color="#836B00">||</font>|                                      IpPermissions                                     |<font color="#836B00">||</font>
<font color="#836B00">||</font>+----------------------------+----------------------------------+------------------------+<font color="#836B00">||</font>
<font color="#836B00">||</font>|          FromPort          |           IpProtocol             |        ToPort          |<font color="#836B00">||</font>
<font color="#836B00">||</font>+----------------------------+----------------------------------+------------------------+<font color="#836B00">||</font>
<font color="#836B00">||</font>|  <font color="#729FCF"><b>3000</b></font>                      |  <font color="#729FCF"><b>tcp</b></font>                             |  <font color="#729FCF"><b>3000</b></font>                  |<font color="#836B00">||</font>
<font color="#836B00">||</font>+----------------------------+----------------------------------+------------------------+<font color="#836B00">||</font>
<font color="#836B00">|||</font>|                                       IpRanges                                       |<font color="#836B00">|||</font>
<font color="#836B00">|||</font>+--------------------------------------------------------------------------------------+<font color="#836B00">|||</font>
<font color="#836B00">|||</font>|                                        CidrIp                                        |<font color="#836B00">|||</font>
<font color="#836B00">|||</font>+--------------------------------------------------------------------------------------+<font color="#836B00">|||</font>
<font color="#836B00">|||</font>|  <font color="#729FCF"><b>75.166.145.22/32</b></font>                                                                    |<font color="#836B00">|||</font>
<font color="#836B00">|||</font>+--------------------------------------------------------------------------------------+<font color="#836B00">|||</font>
<font color="#836B00">||</font>|                                   IpPermissionsEgress                                  |<font color="#836B00">||</font>
<font color="#836B00">||</font>+----------------------------------------------------------------------------------------+<font color="#836B00">||</font>
<font color="#836B00">||</font>|                                       IpProtocol                                       |<font color="#836B00">||</font>
<font color="#836B00">||</font>+----------------------------------------------------------------------------------------+<font color="#836B00">||</font>
<font color="#836B00">||</font>|  <font color="#729FCF"><b>-1</b></font>                                                                                    |<font color="#836B00">||</font>
<font color="#836B00">||</font>+----------------------------------------------------------------------------------------+<font color="#836B00">||</font>
<font color="#836B00">|||</font>|                                       IpRanges                                       |<font color="#836B00">|||</font>
<font color="#836B00">|||</font>+--------------------------------------------------------------------------------------+<font color="#836B00">|||</font>
<font color="#836B00">|||</font>|                                        CidrIp                                        |<font color="#836B00">|||</font>
<font color="#836B00">|||</font>+--------------------------------------------------------------------------------------+<font color="#836B00">|||</font>
<font color="#836B00">|||</font>|  <font color="#729FCF"><b>0.0.0.0/0</b></font>                                                                           |<font color="#836B00">|||</font>
<font color="#836B00">|||</font>+--------------------------------------------------------------------------------------+<font color="#836B00">|||</font>
</pre>

# Create SSH key

1. Create an SSH key pair that will be used to access the EC2 instance.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 create-key-pair --key-name EffectiveDevOpsAWS
{
    &quot;KeyFingerprint&quot;: &quot;99:ee:44:6e:9b:3f:5c:bc:3e:ab:9d:09:d5:c3:6b:28:dc:56:0e:07&quot;,
    &quot;KeyMaterial&quot;: &quot;-----BEGIN RSA PRIVATE KEY-----\n<...snippped...>\n-----END RSA PRIVATE KEY-----&quot;,
    &quot;KeyName&quot;: &quot;EffectiveDevOpsAWS&quot;
}
</pre>

![](https://i.imgur.com/GtMRAol.png)

2. The key is located in the `"KeyMaterial":` section of the JSON output. Use the `echo` command to output it to a PEM file.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ echo -e &quot;-----BEGIN RSA PRIVATE KEY-----\n<...snippped...>\n-----END RSA PRIVATE KEY-----&quot; &gt; ~/.ssh/EffectiveDevOpsAWS.pem
</pre>

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ chmod 600 ~/.ssh/EffectiveDevOpsAWS.pem
</pre>

Verify the fingerprint is the same as that displayed by the EC2 API. The command essentially just converts the private key from PEM (text) to DER (binary) format.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ openssl pkcs8 -in ~/.ssh/EffectiveDevOpsAWS.pem -nocrypt -topk8 -outform DER | openssl sha1 -c
(stdin)= 99:ee:44:6e:9b:3f:5c:bc:3e:ab:9d:09:d5:c3:6b:28:dc:56:0e:07
</pre>

# Launch EC2 instance

1. Launch EC2 Instance with the following information:
- AMI ID: ami-a0cfeed8
- Instance type: t2.micro
- Security Group: sg-077a84bbc6f365e4c
- SSH key-pair: EffectiveDevOps

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 run-instances --instance-type t2.micro --key-name EffectiveDevOpsAWS --security-group-ids sg-0e2799ad580df135d --image-id ami-a0cfeed8
{
    &quot;Groups&quot;: [],
    &quot;Instances&quot;: [
        {
            &quot;AmiLaunchIndex&quot;: 0,
            &quot;ImageId&quot;: &quot;ami-a0cfeed8&quot;,
            &quot;InstanceId&quot;: &quot;i-079f9ae01c99115a7&quot;,
            &quot;InstanceType&quot;: &quot;t2.micro&quot;,
            &quot;KeyName&quot;: &quot;EffectiveDevOpsAWS&quot;,
            &quot;LaunchTime&quot;: &quot;2018-10-17T22:31:44.000Z&quot;,
            &quot;Monitoring&quot;: {
                &quot;State&quot;: &quot;disabled&quot;
            },
            &quot;Placement&quot;: {
                &quot;AvailabilityZone&quot;: &quot;us-west-2a&quot;,
                &quot;GroupName&quot;: &quot;&quot;,
                &quot;Tenancy&quot;: &quot;default&quot;
            },
            &quot;PrivateDnsName&quot;: &quot;ip-172-31-22-252.us-west-2.compute.internal&quot;,
            &quot;PrivateIpAddress&quot;: &quot;172.31.22.252&quot;,
            &quot;ProductCodes&quot;: [],
            &quot;PublicDnsName&quot;: &quot;&quot;,
            &quot;State&quot;: {
                &quot;Code&quot;: 0,
                &quot;Name&quot;: &quot;pending&quot;
            },
            &quot;StateTransitionReason&quot;: &quot;&quot;,
            &quot;SubnetId&quot;: &quot;subnet-718a3a08&quot;,
            &quot;VpcId&quot;: &quot;vpc-b3b5feca&quot;,
            &quot;Architecture&quot;: &quot;x86_64&quot;,
            &quot;BlockDeviceMappings&quot;: [],
            &quot;ClientToken&quot;: &quot;&quot;,
            &quot;EbsOptimized&quot;: false,
            &quot;Hypervisor&quot;: &quot;xen&quot;,
            &quot;NetworkInterfaces&quot;: [
                {
                    &quot;Attachment&quot;: {
                        &quot;AttachTime&quot;: &quot;2018-10-17T22:31:44.000Z&quot;,
                        &quot;AttachmentId&quot;: &quot;eni-attach-063a5cc7d51ce8a90&quot;,
                        &quot;DeleteOnTermination&quot;: true,
                        &quot;DeviceIndex&quot;: 0,
                        &quot;Status&quot;: &quot;attaching&quot;
                    },
                    &quot;Description&quot;: &quot;&quot;,
                    &quot;Groups&quot;: [
                        {
                            &quot;GroupName&quot;: &quot;HelloWorld&quot;,
                            &quot;GroupId&quot;: &quot;sg-0e2799ad580df135d&quot;
                        }
                    ],
                    &quot;Ipv6Addresses&quot;: [],
                    &quot;MacAddress&quot;: &quot;02:38:b1:9e:31:4a&quot;,
                    &quot;NetworkInterfaceId&quot;: &quot;eni-014e58c52f13fcb97&quot;,
                    &quot;OwnerId&quot;: &quot;404297683117&quot;,
                    &quot;PrivateDnsName&quot;: &quot;ip-172-31-22-252.us-west-2.compute.internal&quot;,
                    &quot;PrivateIpAddress&quot;: &quot;172.31.22.252&quot;,
                    &quot;PrivateIpAddresses&quot;: [
                        {
                            &quot;Primary&quot;: true,
                            &quot;PrivateDnsName&quot;: &quot;ip-172-31-22-252.us-west-2.compute.internal&quot;,
                            &quot;PrivateIpAddress&quot;: &quot;172.31.22.252&quot;
                        }
                    ],
                    &quot;SourceDestCheck&quot;: true,
                    &quot;Status&quot;: &quot;in-use&quot;,
                    &quot;SubnetId&quot;: &quot;subnet-718a3a08&quot;,
                    &quot;VpcId&quot;: &quot;vpc-b3b5feca&quot;
                }
            ],
            &quot;RootDeviceName&quot;: &quot;/dev/xvda&quot;,
            &quot;RootDeviceType&quot;: &quot;ebs&quot;,
            &quot;SecurityGroups&quot;: [
                {
                    &quot;GroupName&quot;: &quot;HelloWorld&quot;,
                    &quot;GroupId&quot;: &quot;sg-0e2799ad580df135d&quot;
                }
            ],
            &quot;SourceDestCheck&quot;: true,
            &quot;StateReason&quot;: {
                &quot;Code&quot;: &quot;pending&quot;,
                &quot;Message&quot;: &quot;pending&quot;
            },
            &quot;VirtualizationType&quot;: &quot;hvm&quot;
        }
    ],
    &quot;OwnerId&quot;: &quot;404297683117&quot;,
    &quot;ReservationId&quot;: &quot;r-06b2c73070b3687b7&quot;
}
</pre>

2. Check the status by getting the `InstanceID` from the output of the `aws ec2 run-instances` command. The instance is ready when the `Status` under `SystemStatus` changes from `initializing` to `ok`.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 describe-instance-status --instance-ids i-079f9ae01c99115a7
{
    &quot;InstanceStatuses&quot;: [
        {
            &quot;AvailabilityZone&quot;: &quot;us-west-2a&quot;,
            &quot;InstanceId&quot;: &quot;i-079f9ae01c99115a7&quot;,
            &quot;InstanceState&quot;: {
                &quot;Code&quot;: 16,
                &quot;Name&quot;: &quot;running&quot;
            },
            &quot;InstanceStatus&quot;: {
                &quot;Details&quot;: [
                    {
                        &quot;Name&quot;: &quot;reachability&quot;,
                        &quot;Status&quot;: &quot;initializing&quot;
                    }
                ],
                &quot;Status&quot;: &quot;initializing&quot;
            },
            &quot;SystemStatus&quot;: {
                &quot;Details&quot;: [
                    {
                        &quot;Name&quot;: &quot;reachability&quot;,
                        &quot;Status&quot;: &quot;initializing&quot;
                    }
                ],
                &quot;Status&quot;: &quot;initializing&quot;
            }
        }
    ]
}
</pre>

![](https://i.imgur.com/lF5nth7.png)

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 describe-instance-status --instance-ids i-079f9ae01c99115a7 --query &quot;InstanceStatuses[*].SystemStatus.Status&quot;
[
    &quot;ok&quot;
]
</pre>

## Connect to EC2 instance via SSH

1. Find the DNS name of the EC2 instance.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 describe-instances --instance-ids i-079f9ae01c99115a7 --query &quot;Reservations[*].Instances[*].PublicDnsName&quot;
[
    [
        &quot;ec2-54-189-165-229.us-west-2.compute.amazonaws.com&quot;
    ]
]
</pre>

2. SSH using the default user account for Amazon Linux is `ec2-user`.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ ssh -i ~/.ssh/EffectiveDevOpsAWS.pem ec2-user@ec2-54-189-165-229.us-west-2.compute.amazonaws.com

       __|  __|_  )
       _|  (     /   Amazon Linux AMI
      ___|\___|___|

https://aws.amazon.com/amazon-linux-ami/2018.03-release-notes/
11 package(s) needed for security, out of 20 available
Run &quot;sudo yum update&quot; to apply all updates.
[ec2-user@ip-172-31-22-252 ~]$</pre>

<pre>[ec2-user@ip-172-31-22-252 ~]$ ec2-metadata --all
ami-id: ami-a0cfeed8
ami-launch-index: 0
ami-manifest-path: (unknown)
ancestor-ami-ids: not available
block-device-mapping: 
	 ami: /dev/xvda
	 root: /dev/xvda
instance-id: i-079f9ae01c99115a7
instance-type: t2.micro
local-hostname: ip-172-31-22-252.us-west-2.compute.internal
local-ipv4: 172.31.22.252
kernel-id: not available
placement: us-west-2a
product-codes: not available
public-hostname: ec2-54-189-165-229.us-west-2.compute.amazonaws.com
public-ipv4: 54.189.165.229
public-keys: 
keyname:EffectiveDevOpsAWS
index:0
format:openssh-key
key:(begins from next line)
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCamr79lrbfZBhAHFkqTEgJ7GP6OcCYG0AaojxfBbg4MwNalQ0lGE6k7euFZ/OReIfvFlvthNyIF3gqZnzFsUOkxbHeXVFFGBra3DAEtrbd9xMJGjH47vc6ytiL2+8IgAaIfUa3ec9N1IsFQwrLX/vs3tM/SI5Ld8APkkFChoQbXQPDS4k3AE8wyrSn83Q0+aOAWNXGUdkAWsagMrLhmCSt31AhGdH2hGJE6XZp+XZxNu1c9ThpnTHxvXCznODeonuAKC/acQPigO5fw7DFWITw6oLx5mZfiLNd7U5vyJVQ1J9HzxoMLfA52CcwaJyGLG7wM63BnuHymCwz02YKaK3x EffectiveDevOpsAWS
ramdisk-id: not available
reservation-id: r-06b2c73070b3687b7
security-groups: HelloWorld
user-data: not available
</pre>

## Install node.js

1. Install node.js. Amazon Linux is based on Red Hat Enterprise Linux (RHEL) and uses `yum` utility to manage and install packages. The OS comes with Extra Packages for Enterprise Linux (EPEL) pre-configured in it.

<pre>[ec2-user@ip-172-31-22-252 ~]$ sudo yum install --enablerepo=epel -y nodejs
</pre>

<pre>[ec2-user@ip-172-31-22-252 ~]$ node -v
v0.10.48</pre>

## Run node.js Hello World

1. Download the helloworld code from github.

<pre>[ec2-user@ip-172-31-22-252 ~]$ wget http://bit.ly/2vESNuc -O /home/ec2-user/helloworld.js
</pre>

```javascript=
var http = require("http")

http.createServer(function (request, response) {

   // Send the HTTP header
   // HTTP Status: 200 : OK
   // Content Type: text/plain
   response.writeHead(200, {'Content-Type': 'text/plain'})

   // Send the response body as "Hello World"
   response.end('Hello World\n')
}).listen(3000)

// Console will print the message
console.log('Server running')
```

2. Run the code.

<pre>[ec2-user@ip-172-31-22-252 ~]$ node helloworld.js Server running
Server running
</pre>

3. Navigate to http://ec2-54-189-165-229.us-west-2.compute.amazonaws.com:3000.

![](https://i.imgur.com/3xrkqZd.png)

4. Stop execution of helloworld with Ctrl+C in the terminal window.

<pre>^C[ec2-user@ip-172-31-22-252 ~]$ </pre>

## Turn code into a service using upstart

1. Turn simple code into a service using upstart. Amazon Linux (unlike RHEL) comes with a system called upstart and provides additional features that System-V boot-up scripts don’t have, such as the ability to re-spawn a process that died unexpectedly. Download the helloworld.conf code from github and add the following code to `/etc/init/` on the EC2 instance.

<pre>[ec2-user@ip-172-31-22-252 ~]$ sudo wget http://bit.ly/2vVvT18 -O /etc/init/helloworld.conf</pre>

```bash=
description "Hello world Deamon"

# Start when the system is ready to do networking.
start on started elastic-network-interfaces

# Stop when the system is on its way down.
stop on shutdown

respawn
script
    exec su --session-command="/usr/bin/node /home/ec2-user/helloworld.js" ec2-user
end script  
```
7. Start the application.

<pre>[ec2-user@ip-172-31-22-252 ~]$ sudo start helloworld
helloworld start/running, process 2856
</pre>

2. Service should still work at: http://ec2-54-189-165-229.us-west-2.compute.amazonaws.com:3000.

# Terminate EC2 instance

1. Perform a clean shutdown of Hello World service using the `stop` command, then exit the virtual server.

<pre>[ec2-user@ip-172-31-22-252 ~]$ sudo stop helloworld
helloworld stop/waiting
</pre>

<pre>[ec2-user@ip-172-31-22-252 ~]$ ec2-metadata --instance-id
instance-id: i-079f9ae01c99115a7
</pre>

<pre>[ec2-user@ip-172-31-22-252 ~]$ exit
logout
Connection to ec2-54-189-165-229.us-west-2.compute.amazonaws.com closed.
</pre>

2. Terminate the EC2 instance.

<pre><font color="#8AE234"><b>sean@vubuntu</b></font>:<font color="#729FCF"><b>~</b></font>$ aws ec2 terminate-instances --instance-ids i-079f9ae01c99115a7
{
    &quot;TerminatingInstances&quot;: [
        {
            &quot;CurrentState&quot;: {
                &quot;Code&quot;: 32,
                &quot;Name&quot;: &quot;shutting-down&quot;
            },
            &quot;InstanceId&quot;: &quot;i-079f9ae01c99115a7&quot;,
            &quot;PreviousState&quot;: {
                &quot;Code&quot;: 16,
                &quot;Name&quot;: &quot;running&quot;
            }
        }
    ]
}</pre>

![](https://i.imgur.com/02Jda47.png)

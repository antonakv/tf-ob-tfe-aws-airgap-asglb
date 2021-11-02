#!/usr/bin/env python3

from diagrams import Diagram
from diagrams import Cluster
from diagrams.aws.network import VPC
from diagrams.aws.general import InternetGateway
from diagrams.aws.network import RouteTable
from diagrams.aws.network import NATGateway
from diagrams.aws.network import PrivateSubnet
from diagrams.aws.network import PublicSubnet
from diagrams.aws.compute import EC2ElasticIpAddress
from diagrams.aws.network import RouteTable
from diagrams.aws.network import Route53
from diagrams.aws.storage import SimpleStorageServiceS3Bucket
from diagrams.aws.security import IAMRole
from diagrams.aws.security import ACM
from diagrams.aws.network import ALB
from diagrams.aws.compute import AutoScaling
from diagrams.aws.database import RDSPostgresqlInstance


with Diagram("TFE Airgap ASG LB", show = False, direction="TB"):
    with Cluster("AWS"):
        with Cluster("VPC"):
            InternetGateway("Internet Gateway") >> [RouteTable("aws5-private"),
                                                    RouteTable("aws5-public") >> NATGateway("NAT Gateway")
                                                    ]

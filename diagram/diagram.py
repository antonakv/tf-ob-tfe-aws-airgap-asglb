#!/usr/bin/env python3

from diagrams import Diagram
from diagrams import Cluster
from diagrams.aws.network import VPC
from diagrams.aws.general import InternetGateway
from diagrams.aws.network import RouteTable
from diagrams.aws.network import NATGateway

with Diagram("TFE Airgap ASG LB", show = False, direction="TB"):
    with Cluster("AWS"):
        with Cluster("VPC"):
            InternetGateway("Internet Gateway") >> [RouteTable("aws5-private"),
                                                    RouteTable("aws5-public") >> NATGateway("NAT Gateway")
                                                    ]

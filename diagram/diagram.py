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
from diagrams.aws.network import ALB
from diagrams.aws.compute import AutoScaling
from diagrams.aws.database import RDSPostgresqlInstance
from diagrams.aws.compute import EC2Instance
from diagrams.onprem.network import Internet

graph_attr_diagram = {
    "fontsize": "35"
}

graph_attr_clusters = {
    "fontsize": "25"
}

graph_attr_nodes = {
    "fontsize": "15"
}

with Diagram("TFE Airgap ASG LB", show = False, direction="TB", graph_attr=graph_attr_diagram, node_attr=graph_attr_nodes):
    internet1 = Internet("Internet")
    with Cluster("AWS", graph_attr=graph_attr_clusters):
        s3_data = SimpleStorageServiceS3Bucket("Data")
        s3_logs = SimpleStorageServiceS3Bucket("Logs")
        s3_airgap = SimpleStorageServiceS3Bucket("Airgap")
        route53 = Route53("Route53")
        with Cluster("VPC", graph_attr=graph_attr_clusters):
            igw = InternetGateway("Internet Gateway")
            rt_private_1 = RouteTable("aws5-private-1")
            rt_public_1 = RouteTable("aws5-public-1")
            rt_private_2 = RouteTable("aws5-private-2")
            rt_public_2 = RouteTable("aws5-public-2")
            subnet_private_1 = PrivateSubnet("aws5-private-1")
            subnet_private_2 = PrivateSubnet("aws5-private-2")
            subnet_public_1 = PublicSubnet("aws5-public-1")
            subnet_public_2 = PublicSubnet("aws5-public-2")
            alb = ALB("Application\n Load\n Balancer")
            rdsdn = RDSPostgresqlInstance("Postgresql")
            autoscale = AutoScaling("ASG")
            internet1 >> igw
            route53 >> alb
            with Cluster("Availability Zone 1", graph_attr=graph_attr_clusters):
                ngw1 = NATGateway("NAT Gateway 1")
                ec2_1 = EC2Instance("TFE Instance 1")
                with Cluster("Private subnet 1", graph_attr=graph_attr_clusters):
                    igw >> rt_private_1 >> subnet_private_1 >> ngw1 >> ec2_1 >> rdsdn
                with Cluster("Public subnet 1", graph_attr=graph_attr_clusters):
                    igw >> rt_public_1 >> subnet_public_1 >> alb >> autoscale >> ec2_1 >> [s3_data, s3_logs, s3_airgap]
            with Cluster("Availability Zone 2", graph_attr=graph_attr_clusters):
                ngw2 = NATGateway("NAT Gateway 2")
                ec2_2 = EC2Instance("TFE Instance 2")
                with Cluster("Private subnet 2", graph_attr=graph_attr_clusters):
                    igw >> rt_private_2 >> subnet_private_2 >> ngw2 >> ec2_2 >> rdsdn
                with Cluster("Public subnet 2", graph_attr=graph_attr_clusters):
                    igw >> rt_public_2 >> subnet_public_2 >> alb >> autoscale >> ec2_2 >> [s3_data, s3_logs, s3_airgap]

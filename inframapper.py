#!/usr/bin/python3
"""InfraMapper

This application is designed to collect data from cloud environments
to create infrastructure maps.

GUI Usage:
    To use the GUI run the following command::

        $ python inframapper.py
"""

__version__ = '0.2.0'

import sys
import os
import tempfile
from abc import ABC, abstractmethod
from collections import defaultdict
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QPushButton,
    QFormLayout,
    QComboBox,
    QLineEdit,
    QListWidget,
    QLabel,
    QSplitter,
    QWidget,
    QVBoxLayout,
    QToolBar,
    QGridLayout,
    QMainWindow,
)
from PySide6.QtGui import (
    QIntValidator,
    QPixmap,
)
from diagrams import (
    Cluster,
    Diagram,
)
from diagrams.aws.compute import EC2
from diagrams.aws.general import GenericFirewall
from tqdm import tqdm
import boto3

class CloudConnector(ABC):
    """Amazing docstring"""
    def __init__(self) -> None:
        return

    @abstractmethod
    def verify_session(self) -> bool:
        """Amazing docstring"""
        return

    @abstractmethod
    def generate_map(self, name:str='InfraMap', filename:str=None, show:bool=False) -> None:
        """Amazing docstring"""
        return

    @abstractmethod
    def authenticate(self, profile:str, mfa_enabled:bool=False, mfa_code:int=None) -> None:
        return

class AWSCore(CloudConnector):
    """
    AWS CloudConnector
    Uses boto3 SDK for API calls to services

    Attributes
    ----------
    session : class
        boto3 session object
    session_token : str
        AWS session token for MFA authentication
    profiles : list
        avaliable boto3 profiles
    supported_regions : list
        AWS regions supported by AWSCore
    enabled_regions : list
        AWS regions to query

    Public Methods
    -------
    update_profiles() -> None:
        Updates boto3 profile list from AWS credential file.

    authenticate(profile:str, mfa_enabled:bool=False, mfa_code:int=None) -> None:
        Authenticates to AWS using profile.

        Variables:
            profile : str
                AWS profile to use for authentication.
            mfa_enabled : bool
                (Optional) Boolean to enable or disable MFA.
            mfa_code : int
                (Optional) MFA code to use for authentication.

    generate_map() -> None:
        Generates an infrastructure map.

    verify_session() -> bool:
        Verifies if session is valid.

    """
    def __init__(self, regions:list=['us-east-1']) -> None:
        super().__init__()
        # Define attributes
        self.session = boto3.session.Session()
        self.profiles = self.session.available_profiles
        self.enabled_regions = regions
        self.session_token = None  # Required for MFA only
        self.supported_regions = [
            'us-east-1',
            'us-east-2',
            'eu-west-1',
            'eu-west-2',
        ]

    def update_profiles(self) -> None:
        """Updates AWS profiles from credentials file"""
        self.profiles = boto3.session.Session().available_profiles
        print(self.profiles)  # TBR

    def _create_session(self, profile:str) -> None:
        self.session = boto3.Session(
            profile_name=profile
        )

    def _mfa_auth(self, mfa_code:int) -> None:
        sts = self.session.client('sts')
        # Call the assume_role method of the STSConnection object and pass the role
        # ARN and a role session name.
        assumed_role_object = sts.assume_role(
            RoleSessionName='mysession',  # Needs setting to something sensible
            DurationSeconds=3600,  # Should be via config
            TokenCode=mfa_code,
        )

        # From the response that contains the assumed role, get the temporary
        # credentials that can be used to make subsequent API calls
        credentials = assumed_role_object['Credentials']

        self.session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )

    def authenticate(self, profile:str, mfa_enabled:bool=False, mfa_code:int=None) -> None:
        """Amazing docstring"""
        self._create_session(profile)
        if mfa_enabled:
            self._mfa_auth(mfa_code)
        if not self.verify_session():
            raise Exception('Failed to verify AWS session!')

    def verify_session(self) -> bool:  # Placeholder
        """Amazing docstring"""
        return True

    def generate_map(self, name:str='InfraMap', filename:str=None, show:bool=False) -> None:
        with Diagram(name=name, filename=filename, show=show, direction="TB"):
            # Create empty list variables
            egress_rules = []
            ingress_rules = []

            # Query topology
            # Region
            # ---- VPC
            # -------- Subnet
            # ------------ Instance

            for region in tqdm(self.enabled_regions):
                with Cluster(region):
                    # Create regional ec2 resource object
                    ec2 = self.session.resource('ec2',
                        region_name=region,
                    )

                    for vpc in ec2.vpcs.filter():
                        with Cluster(vpc.vpc_id):
                            subnet_query = ec2.subnets.filter(Filters=[
                                {
                                    'Name': 'vpc-id',
                                    'Values': [vpc.vpc_id]
                                }
                            ])
                            for subnet in subnet_query:
                                with Cluster(f"{subnet.subnet_id} ({subnet.cidr_block})"):

                                    instance_query = ec2.instances.filter(Filters=[
                                        {
                                            'Name': 'subnet-id',
                                            'Values': [subnet.subnet_id]
                                        }
                                    ])

                                    instances = []

                                    for instance in instance_query:
                                        if instance.tags is not None:
                                            for tag in instance.tags:
                                                if 'Name' in tag['Key']:
                                                    name = tag['Value']
                                        else:
                                            name = instance.instance_id

                                        item = EC2(name)
                                        instances.append(item)

                                        # Security Group Processing
                                        for security_group in instance.security_groups:
                                            sg_object = ec2.SecurityGroup(security_group['GroupId'])
                                            for rule in sg_object.ip_permissions_egress:
                                                for ip_range in rule['IpRanges']:
                                                    rule_dict = {
                                                        'EC2Instance': item,
                                                        'CidrRange': ip_range['CidrIp'],
                                                        'IpProtocol': rule['IpProtocol']
                                                    }

                                                    if rule['IpProtocol'] != '-1':
                                                        rule_dict['FromPort'] = rule['FromPort']
                                                        rule_dict['ToPort'] = rule['ToPort']
                                                    egress_rules.append(rule_dict)
                                            for rule in sg_object.ip_permissions:
                                                for ip_range in rule['IpRanges']:
                                                    rule_dict = {
                                                        'EC2Instance': item,
                                                        'CidrRange': ip_range['CidrIp'],
                                                        'IpProtocol': rule['IpProtocol']
                                                    }

                                                    if rule['IpProtocol'] != '-1':
                                                        rule_dict['FromPort'] = rule['FromPort']
                                                        rule_dict['ToPort'] = rule['ToPort']
                                                    ingress_rules.append(rule_dict)

            sources = defaultdict()
            destinations = defaultdict()

            for rule in egress_rules:
                if rule['CidrRange'] not in destinations.keys():
                    destinations[rule['CidrRange']] = {
                        'Object': GenericFirewall(rule['CidrRange']),
                        'Instances': [rule['EC2Instance']]
                    }
                else:
                    if rule['EC2Instance'] not in destinations[rule['CidrRange']]['Instances']:
                        destinations[rule['CidrRange']]['Instances'].append(rule['EC2Instance'])

            for rule in ingress_rules:
                if rule['CidrRange'] not in sources.keys():
                    sources[rule['CidrRange']] = {
                        'Object': GenericFirewall(rule['CidrRange']),
                        'Instances': [rule['EC2Instance']]
                    }
                else:
                    if rule['EC2Instance'] not in sources[rule['CidrRange']]['Instances']:
                        sources[rule['CidrRange']]['Instances'].append(rule['EC2Instance'])

            for source in sources:
                sources[source]['Object'] >> sources[source]['Instances'] # pylint: disable=pointless-statement

            for destination in destinations:
                destinations[destination]['Instances'] >> destinations[destination]['Object'] # pylint: disable=pointless-statement



class GUI(QMainWindow):
    """
    PySide6 GUI interface class

    Attributes
    ----------

    Methods
    -------

    """
    def __init__(self, parent=None) -> None:
        self.cloud_connector = AWSCore()
        self.profile = QWidget()
        self.mfa_enabled = QWidget()
        self.mfa_code = QWidget()
        self.regions = QWidget()
        self.inframap = QLabel()

        super().__init__(parent)

        self._build_gui()

    def _build_gui(self) -> QWidget:
        self.statusBar().showMessage('Building GUI...')

        left_pane = self._create_left_pane()
        right_pane = self._create_right_pane()

        self.statusBar().showMessage('Ready')

        layout_widget = self._build_layout(left_pane=left_pane, right_pane=right_pane)

        self.setCentralWidget(layout_widget)

    def _build_layout(self, left_pane, right_pane) -> QWidget:
        content = QWidget()

        splitter = QSplitter()
        splitter.addWidget(left_pane)
        splitter.addWidget(right_pane)
        splitter.setSizes([100,200])

        layout = QGridLayout(self)
        toolbar = QToolBar()
        update_profiles = QPushButton('Update Profiles')
        update_profiles.clicked.connect(self.cloud_connector.update_profiles)
        toolbar.addWidget(QPushButton('Home'))
        toolbar.addWidget(QPushButton('Map Creator'))
        toolbar.addWidget(update_profiles)
        layout.addWidget(toolbar)
        layout.addWidget(splitter)
        content.setLayout(layout)

        return content

    def _create_right_pane(self) -> QWidget:
        content = QVBoxLayout()  # Layout widget for pane content

        self.inframap = QLabel()

        content.addWidget(self.inframap)

        # Container widget for pane layout
        pane_layout_container = QWidget()
        pane_layout_container.setLayout(content)
        return pane_layout_container


    def _create_left_pane(self) -> QWidget:
        self.profile = QComboBox()
        self.profile.addItems(self.cloud_connector.profiles)
        self.mfa_enabled = QCheckBox()
        self.mfa_code = QLineEdit()
        self.mfa_code.setValidator(QIntValidator())
        self.mfa_code.setMaxLength(6)
        self.mfa_code.setDisabled(True)
        self.regions = QListWidget()
        self.regions.addItems(self.cloud_connector.supported_regions)
        self.regions.setSelectionMode(QListWidget.MultiSelection)
        generate = QPushButton('Generate Map')

        # Add button signal to greetings slot
        self.generate.clicked.connect(self.display_map)
        self.mfa_enabled.stateChanged.connect(self.toggle_mfa)

        # Create layout and add widgets
        content = QFormLayout()
        content.addRow('AWS Profile', self.profile)
        content.addRow('MFA Enabled?', self.mfa_enabled)
        content.addRow('MFA Code', self.mfa_code)
        content.addRow('Regions', self.regions)
        content.addWidget(generate)

        label = QLabel()
        label.setAutoFillBackground(True)

        # UNTIL HERE you populate your content

        # Container widget for pane layout
        pane_layout_container = QWidget()
        pane_layout_container.setLayout(content)
        return pane_layout_container


    def toggle_mfa(self) -> None:
        """Amazing docstring"""
        self.mfa_code.setEnabled(self.mfa_enabled.isChecked())

    def _authenticate(self) -> None:
        profile = self.profile.currentText()
        mfa_enabled = self.mfa_enabled.isChecked()
        mfa_code = self.mfa_code.text()
        regions = []
        for region in self.regions.selectedItems():
            regions.append(region.text())
        self.cloud_connector = AWSCore(regions)
        self.cloud_connector.authenticate(profile, mfa_enabled, mfa_code)

    def display_map(self) -> None:
        self.statusBar().showMessage('Authenticating...')
        self._authenticate()
        self.statusBar().showMessage('Creating Map...')
        with tempfile.TemporaryDirectory() as temp_dir:
            filepath = os.path.join(temp_dir,'InfraMap')
            self.cloud_connector.generate_map(filename=filepath)
            infra_pixmap = QPixmap(f'{filepath}.png')
            self.inframap.setPixmap(infra_pixmap)
        self.statusBar().showMessage('Ready')


if __name__ == '__main__':
    # Create the Qt Application
    app = QApplication(sys.argv)
    # Create and show the form
    form = GUI()
    form.show()
    # Run the main Qt loop
    sys.exit(app.exec())

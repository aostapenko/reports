#!/usr/bin/python2.7
import argparse
import calendar
import logging
import os
import pprint
import sys
import time

from ceilometerclient import client as ceilometer_client
from influxdb import InfluxDBClient
from keystoneauth1 import discover
from keystoneauth1.identity import v2
from keystoneauth1.identity import v3
from keystoneauth1 import session


logger = logging.getLogger(__file__)
logging.basicConfig()
logger.setLevel(logging.INFO)


parser = argparse.ArgumentParser()

parser.add_argument("--os_username",
                    default=os.environ.get("OS_USERNAME", "admin"),
                    help="Openstack username")
parser.add_argument("--os_password",
                    default=os.environ.get("OS_PASSWORD", "admin"),
                    help="Openstack password")
parser.add_argument("--os_auth_url",
                    default=os.environ.get("OS_AUTH_URL",
                                           "http://localhost:5000"),
                    help="Openstack authentification url")
parser.add_argument("--os_endpoint_type",
                    default=os.environ.get("OS_ENDPOINT_TYPE",
                                           "internalURL"),
                    help="Endpoint type")
parser.add_argument("--os_project_name",
                    default=os.environ.get("OS_PROJECT_NAME", "admin"),
                    help="Name of admin project for auth")
parser.add_argument("--os_user_domain_id",
                    help="User domain id")
parser.add_argument("--os_project_domain_id",
                    help="Project domain id")

parser.add_argument("--influxdb_host",
                    default=os.environ.get("INFLUXDB_HOST",
                                           "172.16.107.4"),
                    help="InfluxDB host")
parser.add_argument("--influxdb_port",
                    default=os.environ.get("INFLUXDB_PORT",
                                           "8086"),
                    help="InfluxDB port")
parser.add_argument("--influxdb_username",
                    default=os.environ.get("INFLUXDB_USER",
                                           "lma"),
                    help="InfluxDB username")
parser.add_argument("--influxdb_password",
                    default=os.environ.get("INFLUXDB_PASSWORD",
                                           "ieFrFc7An2ooWGBE8FTGGn7y"),
                    help="InfluxDB password")
parser.add_argument("--influxdb_source_dbname",
                    default=os.environ.get("INFLUXDB_INPUT_DB_NAME",
                                           "lma"),
                    help="InfluxDB source database name")
parser.add_argument("--influxdb_dest_dbname",
                    default=os.environ.get("INFLUXDB_OUTPUT_DB_NAME",
                                           "lma"),
                    help="InfluxDB destination database name")


def _discover_auth_versions(session, auth_url):
    ks_discover = discover.Discover(session=session, url=auth_url)
    v2_auth_url = ks_discover.url_for('2.0')
    v3_auth_url = ks_discover.url_for('3.0')
    return v2_auth_url, v3_auth_url


def cut_arg_names(prefix):
    # adapter between script and class arguments
    def decorator(f):
        def wrapper(self, **kwargs):
            new_kwargs = {}
            for k, v in kwargs.items():
                k = k.replace(prefix, '', 1) if k.startswith(prefix) else k
                new_kwargs[k] = v
            return f(self, **new_kwargs)
        return wrapper
    return decorator


class DataProcessor(object):

    def __init__(self, **kwargs):
        super(DataProcessor, self).__init__()
        self._init_os_clients(**kwargs)
        self._init_influx_clients(**kwargs)
        self.gb_period = '1000y'

    @cut_arg_names('influxdb_')
    def _init_influx_clients(self, host, port, username, password,
                             source_dbname, dest_dbname, **kwargs):
        self.source_db_client = InfluxDBClient(host, port, username,
                                               password, source_dbname)
        self.dest_db_client = InfluxDBClient(host, port, username,
                                             password, dest_dbname)

    @cut_arg_names('os_')
    def _init_os_clients(self, username, password, auth_url, project_name,
                         user_domain_id=None, project_domain_id=None,
                         endpoint_type='publicURL', **kwargs):
        sess = session.Session()
        v2_auth_url, v3_auth_url = _discover_auth_versions(sess, auth_url)
        use_domain = user_domain_id or project_domain_id
        use_v3 = v3_auth_url and (use_domain or (not v2_auth_url))
        use_v2 = v2_auth_url and not use_domain

        if use_v3:
            auth = v3.Password(auth_url=v3_auth_url, username=username,
                               password=password, project_name=project_name,
                               user_domain_id=user_domain_id,
                               project_domain_id=project_domain_id)
        elif use_v2:
            auth = v2.Password(v2_auth_url, username, password,
                               tenant_name=project_name)
        else:
            raise Exception('Unable to determine the Keystone version '
                            'to authenticate with using the given auth_url.')

        sess.auth = auth
        self.ceilometer = ceilometer_client.get_client(2, session=sess,
                                                       endpoint_type=endpoint_type)


def main():
    args = parser.parse_args()
    data_processor = DataProcessor(**args.__dict__)


if __name__ == "__main__":
    main()

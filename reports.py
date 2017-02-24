import abc
import argparse
import logging
import os
import pprint
import sys

from ceilometerclient import client as ceilometer_client
from keystoneauth1 import discover
from keystoneauth1.identity import v2
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as keystone_client
from novaclient import client as nova_client


logger = logging.getLogger(__file__)
logging.basicConfig()
logger.setLevel(logging.INFO)


parser = argparse.ArgumentParser()

parser.add_argument("--reports",
                    default='all',
                    help="Report to make. Choose from: all, used_flavors, "
                         "host_instances_count, nova_api_request_rate, "
                         "swift_api_request_rate, storage_io. Can be "
                         "specified several using comma. Default: all")
parser.add_argument("--os_username",
                    default=os.environ.get("OS_USERNAME", "admin"),
                    help="Name of the user")
parser.add_argument("--os_password",
                    default=os.environ.get("OS_PASSWORD", "admin"),
                    help="Password for the user")
parser.add_argument("--os_auth_url",
                    default=os.environ.get("OS_AUTH_URL",
                                           "http://localhost:5000"),
                    help="Openstack authentification url")
parser.add_argument("--os_endpoint_type",
                    default=os.environ.get("OS_ENDPOINT_TYPE",
                                           "internalURL"),
                    help="Endpoint type")
parser.add_argument("--os_admin_project_name",
                    default=os.environ.get("OS_PROJECT_NAME", "admin"),
                    help="Name of admin project for auth")
parser.add_argument("--os_user_domain_id",
                    help="User domain id")
parser.add_argument("--os_project_domain_id",
                    help="Project domain id")
parser.add_argument("--period_start",
                    help="Time when period starts in format "
                         "<YYYY-MM-DDThh:mm:ss> e.g. 2017-01-12T00:00:00")
parser.add_argument("--period_end",
                    help="Time when period ends in format "
                         "<YYYY-MM-DDThh:mm:ss> e.g. 2017-01-13T00:00:00")

parser.add_argument("--influxdb_host",
                    default=os.environ.get("INFLUXDB_HOST",
                                           "localhost"),
                    help="InfluxDB host")
parser.add_argument("--influxdb_port",
                    default=os.environ.get("INFLUXDB_PORT",
                                           "8086"),
                    help="InfluxDB port")
parser.add_argument("--influxdb_db_name",
                    default=os.environ.get("INFLUXDB_DB_NAME",
                                           "lma"),
                    help="InfluxDB database name")
parser.add_argument("--influxdb_user",
                    default=os.environ.get("INFLUXDB_USER",
                                           "lma"),
                    help="InfluxDB user")
parser.add_argument("--influxdb_password",
                    default=os.environ.get("INFLUXDB_PASSWORD",
                                           "secret"),
                    help="InfluxDB password")


def _discover_auth_versions(session, auth_url):
    ks_discover = discover.Discover(session=session, url=auth_url)
    v2_auth_url = ks_discover.url_for('2.0')
    v3_auth_url = ks_discover.url_for('3.0')
    return v2_auth_url, v3_auth_url


class AbstractComputeReport(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def used_flavors(self):
        pass

    @abc.abstractmethod
    def host_instances_count(self):
        pass


class BaseComputeReport(AbstractComputeReport):

    AVAILABLE_REPORTS = ('host_instances_count', 'used_flavors')

    def __init__(self, username, password, auth_url, project_name,
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
        self.keystone = keystone_client.Client(session=sess)
        self.nova = nova_client.Client(2, session=sess,
                                       endpoint_type=endpoint_type)
        self.cclient = ceilometer_client.get_client(2, session=sess,
                                                    endpoint_type=endpoint_type)


class PeriodBasedComputeReport(BaseComputeReport):

    def __init__(self, period_start=None, period_end=None, **kwargs):
        super(PeriodBasedComputeReport, self).__init__(**kwargs)
        self.query = self._get_query(period_start, period_end)

    def _get_query(self, period_start=None, period_end=None):
        query = [dict(field="metadata.state", op="eq", value="active")]
        if period_start:
            query.append(dict(field="timestamp", op="gt", value=period_start))
        if period_end:
            query.append(dict(field="timestamp", op="lt", value=period_end))
        return query

    def host_instances_count(self):
        hypervisors = self.nova.hypervisors.list()
        host_instances_count = {}
        for hypervisor in hypervisors:
            host = hypervisor.service['host']
            host_query = [dict(field="metadata.instance_host", op="eq",
                               value=host)]
            statistics = self.cclient.statistics.list(
                'instance', q=self.query+host_query, groupby='resource_id')
            host_instances_count[host] = len(statistics)
        return host_instances_count

    def used_flavors(self):
        statistics = self.cclient.statistics.list(
            'instance',
            q=self.query,
            groupby=('resource_id', 'resource_metadata.instance_type')
        )
        instance_type_count = {}
        for s in statistics:
            instance_type = s.groupby['resource_metadata.instance_type']
            instance_type_count.setdefault(instance_type, 0)
            instance_type_count[instance_type] += 1
        return instance_type_count


class CurrentStateComputeReport(BaseComputeReport):

    def __init__(self, **kwargs):
        super(CurrentStateComputeReport, self).__init__(**kwargs)
        self._instance_list = None

    @property
    def instance_list(self):
        if self._instance_list is None:
            self._instance_list = self.nova.servers.list(limit=-1)
        return self._instance_list

    def host_instances_count(self):
        hypervisors = self.nova.hypervisors.list()
        host_instances_count = {h.service['host']: 0 for h in hypervisors}
        for instance in self.instance_list:
            host = instance.to_dict()['OS-EXT-SRV-ATTR:host']
            host_instances_count[host] += 1
        return host_instances_count

    def used_flavors(self):
        flavors = {f.id: f.name for f in self.nova.flavors.list()}
        instance_type_count = {}
        for instance in self.instance_list:
            flavor_name = flavors[instance.flavor['id']]
            instance_type_count.setdefault(flavor_name, 0)
            instance_type_count[flavor_name] += 1
        return instance_type_count


def main():
    args = parser.parse_args()
    if args.period_start or args.period_end:
        compute_reports_class = PeriodBasedComputeReport
    else:
        compute_reports_class = CurrentStateComputeReport
        logger.info("Period not specified. Current state report will be made.")

    r = compute_reports_class(
         username=args.os_username, password=args.os_password,
         auth_url=args.os_auth_url, project_name=args.os_admin_project_name,
         user_domain_id=args.os_user_domain_id,
         project_domain_id=args.os_project_domain_id,
         endpoint_type=args.os_endpoint_type,
         period_start=args.period_start, period_end=args.period_end)
    reports = args.reports
    if reports == 'all':
        reports = r.AVAILABLE_REPORTS
    else:
        reports = reports.split(",")
    bad_reports = set(reports) - set(r.AVAILABLE_REPORTS)
    if bad_reports:
        logger.error("Bad reports: %s" % ', '.join(bad_reports))
        sys.exit(1)

    result = {}
    for report in reports:
        result[report] = getattr(r, report)()

    pprint.pprint(result)


if __name__ == "__main__":
    main()

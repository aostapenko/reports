import argparse
import calendar
import csv
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
from keystoneclient.v3 import client as keystone_client
from novaclient import client as nova_client


logger = logging.getLogger(__file__)
logging.basicConfig()
logger.setLevel(logging.INFO)


parser = argparse.ArgumentParser()

parser.add_argument("--report_type",
                    default='all',
                    choices=['all', 'os_report', 'influxdb_report'],
                    help="Reports to make. Default: all")
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
parser.add_argument("--os_project_name",
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
parser.add_argument("--period",
                    default='1h',
                    choices=['1m', '1h', '1d'],
                    help="Period to use. Default: 1h")
parser.add_argument("--use_time_boundaries",
                    action='store_true',
                    default=False,
                    help="If true, InfluxDB time boundaries will be used")
parser.add_argument("--status_codes",
                    action='store_true',
                    default=False,
                    help="If true, api requests count will be additionally "
                         "grouped by response status codes")

parser.add_argument("--influxdb_host",
                    default=os.environ.get("INFLUXDB_HOST",
                                           "172.16.107.4"),
                    help="InfluxDB host")
parser.add_argument("--influxdb_port",
                    default=os.environ.get("INFLUXDB_PORT",
                                           "8086"),
                    help="InfluxDB port")
parser.add_argument("--influxdb_dbname",
                    default=os.environ.get("INFLUXDB_DB_NAME",
                                           "lma"),
                    help="InfluxDB database name")
parser.add_argument("--influxdb_user",
                    default=os.environ.get("INFLUXDB_USER",
                                           "lma"),
                    help="InfluxDB user")
parser.add_argument("--influxdb_password",
                    default=os.environ.get("INFLUXDB_PASSWORD",
                                           "ieFrFc7An2ooWGBE8FTGGn7y"),
                    help="InfluxDB password")


def _discover_auth_versions(session, auth_url):
    ks_discover = discover.Discover(session=session, url=auth_url)
    v2_auth_url = ks_discover.url_for('2.0')
    v3_auth_url = ks_discover.url_for('3.0')
    return v2_auth_url, v3_auth_url


class BaseReport(object):

    AVAILABLE_REPORTS = ()

    def get_reports(self):
        result = {}
        for method in self.AVAILABLE_REPORTS:
            report = self.REPORT_NAME_TEMPLATE % method
            result[report] = getattr(self, method)()
        return result


def cut_var_name(prefix):
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


class BaseComputeReport(BaseReport):

    @cut_var_name('os_')
    def __init__(self, username, password, auth_url, project_name,
                 user_domain_id=None, project_domain_id=None,
                 endpoint_type='publicURL', **kwargs):
        super(BaseComputeReport, self).__init__()
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

    AVAILABLE_REPORTS = (#'host_unique_instances_sum',
                         'used_flavors',)
    REPORT_NAME_TEMPLATE = 'ceilometer__%s_per_period'

    def __init__(self, period_start=None, period_end=None, **kwargs):
        super(PeriodBasedComputeReport, self).__init__(**kwargs)
        self._setup_time_args(period_start, period_end)
        self.query = self._get_query()

    def _get_query(self):
        query = [dict(field="metadata.state", op="eq", value="active")]
        query.append(dict(field="timestamp", op="gt", value=self.period_start))
        query.append(dict(field="timestamp", op="lt", value=self.period_end))
        return query

    def _wrap_into_period(self, result):
        return {'%s--%s' % (self.period_start, self.period_end): result}
#
#    def host_unique_instances_sum(self):
#        hypervisors = self.nova.hypervisors.list()
#        host_instances_count = {}
#        for hypervisor in hypervisors:
#            host = hypervisor.service['host']
#            host_query = [dict(field="metadata.instance_host", op="eq",
#                               value=host)]
#            statistics = self.cclient.statistics.list(
#                'instance', q=self.query+host_query, groupby='resource_id')
#            host_instances_count[host] = len(statistics)
#        return self._wrap_into_period(host_instances_count)

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
        return self._wrap_into_period(instance_type_count)

    def _setup_time_args(self, period_start, period_end):
        period_start = _adapt_format(period_start)
        period_end = _adapt_format(period_end)

        # we need this logic to consider script execution time to take
        # exactly 1 hour statistics when period is not specified
        if period_end:
            self.period_end = period_end
            period_end_struct = time.strptime(period_end, TIME_FORMAT)
        else:
            current_time = time.time()
            period_end_struct = time.gmtime(current_time)
            self.period_end = time.strftime(TIME_FORMAT, period_end_struct)

        if period_start:
            self.period_start = period_start
            period_start_struct = time.strptime(period_start, TIME_FORMAT)
        else:
            period_start_struct = time.gmtime(
                calendar.timegm(period_end_struct)-self.TIME_MAP[self.period])
            self.period_start = time.strftime(TIME_FORMAT, period_start_struct)


class CurrentStateComputeReport(BaseComputeReport):

    AVAILABLE_REPORTS = ('host_instances_count', 'used_flavors')
    REPORT_NAME_TEMPLATE = 'nova__%s'

    def __init__(self, **kwargs):
        super(CurrentStateComputeReport, self).__init__(**kwargs)
        self._instance_list = None

    @property
    def instance_list(self):
        if self._instance_list is None:
            # no pagination yet
            self._instance_list = self.nova.servers.list(limit=-1)
        return self._instance_list

    def host_instances_count(self):
        hypervisors = self.nova.hypervisors.list()
        host_instances_count = {h.service['host']: 0 for h in hypervisors}
        for instance in self.instance_list:
            host = instance.to_dict()['OS-EXT-SRV-ATTR:host']
            host_instances_count[host] += 1
        return {'current': host_instances_count}

    def used_flavors(self):
        flavors = {f.id: f.name for f in self.nova.flavors.list()}
        instance_type_count = {}
        for instance in self.instance_list:
            flavor_name = flavors[instance.flavor['id']]
            instance_type_count.setdefault(flavor_name, 0)
            instance_type_count[flavor_name] += 1
        return {'current': instance_type_count}


class InfrastructureReport(BaseReport):

    AVAILABLE_REPORTS = (
        'host_instances_count',
        'compute_api_request_count',
        'object_storage_api_request_count',
        'block_storage_api_request_count',
        'storage_io',
    )
    REPORT_NAME_TEMPLATE = 'influxdb__%s_per_period'
    TIME_MAP = {'1m': 60,
                '1h': 3600,
                '1d': 86400,}

    @cut_var_name('influxdb_')
    def __init__(self, host, port, user, password, dbname,
                 period_start=None, period_end=None,
                 period='1h', use_time_boundaries=False,
                 status_codes=False, **kwargs):
        super(InfrastructureReport, self).__init__()
        self.period = period
        self.gb_offset = 0
        self.status_codes = status_codes
        self.use_time_boundaries = use_time_boundaries
        self._setup_time_args(period_start, period_end, period)
        self.client = InfluxDBClient(host, port, user, password, dbname)

    def _query(self, query):
        return self.client.query(query=query).raw.get('series', [])

    def storage_io(self):
        result = self._pool_rates()
#        osd_perf_report = self._osd_perf()
#        for k, v in result.items():
#            v.update(osd_perf_report.get(k, {}))
        return result

    def _osd_perf(self):
        measurements = (
            'ceph_perf_osd_op_r',
            'ceph_perf_osd_op_r_out_bytes',
            'ceph_perf_osd_op_r_latency',
            'ceph_perf_osd_op_r_process_latency',
            'ceph_perf_osd_op_w',
            'ceph_perf_osd_op_w_latency',
            'ceph_perf_osd_op_w_in_bytes',
            'ceph_perf_osd_op_w_process_latency',
        )
        result = {}
        for measurement in measurements:
            query_string = self._get_query(
                measurement=measurement,
                select='sum(value), max(value)',
                gb_tags=('pool',))
            query = self._query(query_string)
            res = {}
            for q in query:
                values = q.get('values', [])
                if not values:
                    continue
                for value in values:
                    time, mean, max  = value
                    result.setdefault(time, {})
                    result[time].setdefault(measurement, {})
                    result[time][measurement] = {'average': mean,
                                                 'maximum': max}
        return result

    # B/s, B/s, op/s
    def _pool_rates(self):
        measurements = ('ceph_pool_bytes_rate_tx',
                        'ceph_pool_bytes_rate_rx',
                        'ceph_pool_ops_rate')
        result = {}
        for measurement in measurements:
            query_string = self._get_query(
                measurement=measurement,
                select='mean(value), max(value)',
                gb_tags=('pool',))
            query = self._query(query_string)
            for q in query:
                values = q.get('values', [])
                if not values:
                    continue
                for i in range(len(values)):
                    start_time, mean, max  = values[i]
                    try:
                        end_time = values[i+1][0]
                    except IndexError:
                        end_time = self.period_end
                    time = '%s--%s' % (start_time, end_time)
                    pool = q['tags']['pool']
                    result.setdefault(time, {})
                    result[time].setdefault(measurement, {})
                    result[time][measurement][pool] = {'average': mean,
                                                       'maximum': max}
        return result

    def host_instances_count(self):
        query_string = self._get_query(
            measurement='openstack_nova_running_instances',
            select='mean(value), max(value)',
            gb_tags=('hostname',))
        query = self._query(query_string)
        result = {}
        for q in query:
            values = q.get('values', [])
            if not values:
                continue
            for i in range(len(values)):
                start_time, mean, max  = values[i]
                try:
                    end_time = values[i+1][0]
                except IndexError:
                    end_time = self.period_end
                time = '%s--%s' % (start_time, end_time)
                hostname = q['tags']['hostname']
                result.setdefault(time, {})
                result[time][hostname] = {'average': mean, 'maximum': max}
        return result

    def compute_api_request_count(self):
        return self._request_count('nova-api')

    def block_storage_api_request_count(self):
        return self._request_count('cinder-api')

    def object_storage_api_request_count(self):
        return self._request_count('object-storage')

    def _request_count(self, service):
        results = {}
        for i in range(1, 6):
            response_code = '%sxx' % i
            measurement = 'haproxy_backend_response_' + response_code
            query_string = self._get_query(
                measurement=measurement,
                select='spread("value")',
                where=("value > 0", "backend = '%s'" % service))
            query = self._query(query_string)
            res = {}
            for q in query:
                values = q.get('values', [])
                if not values:
                    continue
                for i in range(len(values)):
                    start_time, value  = values[i]
                    try:
                        end_time = values[i+1][0]
                    except IndexError:
                        end_time = self.period_end
                    time = '%s--%s' % (start_time, end_time)
                    res.setdefault(time, {})
                    res[time] = value
            results[response_code] = res
        # swapping http_codes and time, removing 0 values
        temp_results = {}
        for status_code, d in results.items():
            for t, count in d.items():
                if not count:
                    continue
                temp_results.setdefault(t, {})
                temp_results[t][status_code] = count
        results = temp_results

        if self.status_codes:
            return results

        # sum different status codes responses
        for t, d in results.items():
            results[t] = sum(d.values())
        return results

    def _adapt_format(self, period):
        if not period:
            return
        return period if period.endswith('Z') else period + 'Z'

    def _setup_time_args(self, period_start, period_end, period):
        period_start = _adapt_format(period_start)
        period_end = _adapt_format(period_end)

        # we need this logic to consider script execution time to take
        # exactly 1 hour statistics when period is not specified
        if period_end:
            self.period_end = period_end
            period_end_struct = time.strptime(period_end, TIME_FORMAT)
        else:
            current_time = time.time()
            period_end_struct = time.gmtime(current_time)
            self.period_end = time.strftime(TIME_FORMAT, period_end_struct)

        if period_start:
            self.period_start = period_start
            period_start_struct = time.strptime(period_start, TIME_FORMAT)
        else:
            period_start_struct = time.gmtime(
                calendar.timegm(period_end_struct)-self.TIME_MAP[self.period])
            self.period_start = time.strftime(TIME_FORMAT, period_start_struct)

        # period logic may be improved to support different periods
        if not self.use_time_boundaries:
            self.gb_offset = period_start_struct.tm_sec
            if self.period in ('1h', '1d'):
                self.gb_offset += period_start_struct.tm_min * 60
            if self.period == '1d':
                self.gb_offset += period_start_struct.tm_hour * 3600

    def _get_query(self, measurement, select, where=None, gb_tags=None):
        query = 'SELECT %s FROM %s WHERE ' % (select, measurement)
        if where:
            for w in where:
                query += w + " AND "
        query += (
            'time >= \'%(period_start)s\''
            ' AND time < \'%(period_end)s\''
            ' GROUP BY time(%(period)s, %(gb_offset)ss)'
        ) % self.__dict__
        if gb_tags:
            for tag in gb_tags:
                query += ',%s' % tag
        query += ' fill(0)'
        return query


def _adapt_format(period):
    if not period:
        return
    return period if period.endswith('Z') else period + 'Z'


TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

REPORT_TYPES_MAP = {
    'period': {
         'os_report': PeriodBasedComputeReport,
         'influxdb_report': InfrastructureReport,
    },
    'current': {
         'os_report': CurrentStateComputeReport,
         'influxdb_report': InfrastructureReport,
    },
}


def write_cvs_report(report):
    reports_dir = os.path.join(os.getcwd(), 'reports')
    if not os.path.isdir(reports_dir):
        os.mkdir(reports_dir)
    report_dirs_list = [d for d in os.listdir(reports_dir)
                        if d.startswith('report-')]
    if report_dirs_list:
        dir_idx = max([
            int(d.split('-')[1])
            for d in report_dirs_list]) + 1
    else:
        dir_idx = 1
    os.mkdir(os.path.join(reports_dir, 'report-%s' % dir_idx))
    influxdb_reports = []

def main():
    args = parser.parse_args()
    if args.period_start or args.period_end:
        report_types_map = REPORT_TYPES_MAP['period']
    else:
        report_types_map = REPORT_TYPES_MAP['current']

    if args.report_type == 'all':
        report_types = report_types_map.keys()
    else:
        report_types = (args.report_type,)

    reports = {}
    for report_type in report_types:
        r = report_types_map[report_type](**args.__dict__)
        reports.update(r.get_reports())

    write_cvs_report(reports)

    pprint.pprint(reports)


if __name__ == "__main__":
    main()

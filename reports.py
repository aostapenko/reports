#!/usr/bin/python2.7
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
                    help="Period to use if period_start or period_end "
                         "not specified. Default: 1h")
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
        for method, descr in self.AVAILABLE_REPORTS:
            report = self.REPORT_NAME_TEMPLATE % method
            result[(report, descr)] = getattr(self, method)()
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

# TODO Make flexible periods
def _calculate_time_borders(period_start, period_end, period):
    # TODO Make flexible periods
    TIME_MAP = {'1m': 60,
                '1h': 3600,
                '1d': 86400,}
    period_start = _adapt_format(period_start)
    period_end = _adapt_format(period_end)

    # we need this logic to consider script execution time to take
    # exactly 1 hour statistics when period is not specified
    if period_start:
        period_start_struct = time.strptime(period_start, TIME_FORMAT)
        period_start_sec = calendar.timegm(period_start_struct)

    if period_end:
        period_end_struct = time.strptime(period_end, TIME_FORMAT)
        period_end_sec = calendar.timegm(period_end_struct)
    else:
        if period_start:
            period_end_sec = period_start_sec + TIME_MAP[period]
        else:
            period_end_sec = time.time()
        period_end_struct = time.gmtime(period_end_sec)
        period_end = time.strftime(TIME_FORMAT, period_end_struct)

    if not period_start:
        period_start_sec = period_end_sec - TIME_MAP[period]
        period_start_struct = time.gmtime(period_start_sec)
        period_start = time.strftime(TIME_FORMAT, period_start_struct)
    return period_start, period_end


class CurrentStateComputeReport(BaseComputeReport):

    AVAILABLE_REPORTS = (
        ('host_instances_count',
         'Current instance number on each host'),
        ('used_flavors',
         'Current report for used instance types'),
    )
    REPORT_NAME_TEMPLATE = 'nova__%s'

    def __init__(self, **kwargs):
        super(CurrentStateComputeReport, self).__init__(**kwargs)
        self._instance_list = None

    @property
    def instance_list(self):
        if self._instance_list is None:
            # TODO Add pagination
            self._instance_list = self.nova.servers.list(limit=-1)
        return self._instance_list

    def host_instances_count(self):
        hypervisors = self.nova.hypervisors.list()
        host_instances_count = {h.service['host']: {'Instance number': 0} for h in hypervisors}
        for instance in self.instance_list:
            host = instance.to_dict()['OS-EXT-SRV-ATTR:host']
            host_instances_count[host]['Instance number'] += 1
        return host_instances_count

    def used_flavors(self):
        flavors = {f.id: f.name for f in self.nova.flavors.list()}
        instance_type_count = {}
        for instance in self.instance_list:
            flavor_name = flavors[instance.flavor['id']]
            instance_type_count.setdefault(flavor_name, {'Instance number': 0})
            instance_type_count[flavor_name]['Instance number'] += 1
        return instance_type_count


# TODO Rename
class PeriodBasedComputeReport(BaseComputeReport):

    AVAILABLE_REPORTS = (
        ('used_flavors',
         'Statistics for instance types for period '),
    )
    REPORT_NAME_TEMPLATE = 'ceilometer__%s_per_period'

    def __init__(self, start_time=None, end_time=None, **kwargs):
        super(PeriodBasedComputeReport, self).__init__(**kwargs)
        self.period_start, self.period_end = start_time, end_time
        self.query = self._get_query()

    def _get_query(self):
        query = [dict(field="metadata.state", op="eq", value="active")]
        query.append(dict(field="timestamp", op="gt", value=self.period_start))
        query.append(dict(field="timestamp", op="lt", value=self.period_end))
        return query

    def used_flavors(self):
        statistics = self.cclient.statistics.list(
            'instance',
            q=self.query,
            groupby=('resource_id', 'resource_metadata.instance_type')
        )
        instance_type_count = {}
        for s in statistics:
            instance_type = s.groupby['resource_metadata.instance_type']
            instance_type_count.setdefault(instance_type, {'Instance number': 0})
            instance_type_count[instance_type]['Instance number'] += 1
        return instance_type_count


# TODO Rename
class InfrastructureReport(BaseReport):

    AVAILABLE_REPORTS = (
        ('host_instances_count',
         'Avarage and maximum instance number on each host for period'),
        ('api_services_request_count',
         'API services number of requests for each hour for period'),
        ('storage_io',
         'Ceph pools bytes and operations rate for period'),
    )
    REPORT_NAME_TEMPLATE = 'influxdb__%s_per_period'

    @cut_var_name('influxdb_')
    def __init__(self, host, port, user, password, dbname,
                 start_time=None, end_time=None,
                 status_codes=False, **kwargs):
        super(InfrastructureReport, self).__init__()
        self.gb_period = '1000y'
        self.status_codes = status_codes
        self.period_start, self.period_end = start_time, end_time
        self.client = InfluxDBClient(host, port, user, password, dbname)

    def _query(self, query):
        return self.client.query(query=query).raw.get('series', [])

    def storage_io(self):
        result = self._pool_rates()
#        result.append({'pools': self._pool_rates()})
#        osd_perf_report = self._osd_perf()
#        for k, v in result.items():
#            v.update(osd_perf_report.get(k, {}))
        return result

#    def _osd_perf(self):
#        measurements = (
#            'ceph_perf_osd_op_r',
#            'ceph_perf_osd_op_r_out_bytes',
#            'ceph_perf_osd_op_r_latency',
#            'ceph_perf_osd_op_r_process_latency',
#            'ceph_perf_osd_op_w',
#            'ceph_perf_osd_op_w_latency',
#            'ceph_perf_osd_op_w_in_bytes',
#            'ceph_perf_osd_op_w_process_latency',
#        )

    def _process_query(self, query, keys, tag_key=None, tag_value=None,
                       metric=None, gb_time=False):
        result = {}
        if metric:
            keys = [' '.join([metric, key]) for key in keys]
        for q in query:
            values = q.get('values', [])
            for i, value in enumerate(values):
                prepared_values = dict(zip(keys, value[1:]))
                tag = q.get('tags', {}).get(tag_key) or tag_value
                if tag:
                    prepared_values = {tag: prepared_values}
                if gb_time:
                    time = value[0]
                    prepared_values = {time: prepared_values}
                result.update(prepared_values)
        return result

    # add units: B/s, B/s, op/s
    def _pool_rates(self):
        metrics = (
            'ceph_pool_bytes_rate_tx',
            'ceph_pool_bytes_rate_rx',
            'ceph_pool_ops_rate',
        )
        result = {}
        tag_key = 'pool'
        aggregates = (('mean', 'value'), ('max', 'value'))
        for metric in metrics:
            query_string = self._compile_query(
                measurement=metric,
                select=aggregates,
                gb_tag=tag_key)
            query = self._query(query_string)
            res = self._process_query(
                query, ('avg', 'max'), tag_key=tag_key, metric=metric)
            for k, v in res.items():
                result.setdefault(k, {})
                result[k].update(v)
        return result

    def host_instances_count(self):
        aggregates = (('mean', 'value'), ('max', 'value'))
        tag_key = 'hostname'
        query_string = self._compile_query(
            measurement='openstack_nova_running_instances',
            select=aggregates,
            gb_tag=tag_key)
        query = self._query(query_string)
        result = self._process_query(query, ('avg', 'max'), tag_key=tag_key,
                                     metric='Instance number')
        return result

    def api_services_request_count(self):
        services = (
            'nova-api',
            'cinder-api',
            'object-storage',
            'glance-api',
            'neutron-api',
        )
        result = {}
        for service in services:
            result.update(self._request_count(service))
        return result

    def _request_count(self, service):
        result = {}
        aggregates = ('last(value) - min(value) + max(value) - first(value), spread(value)')
        key_desc = 'request number'
        # This metrics are counters by each haproxy node that reset unpredictably
        for i in range(1, 6):
            response_code = '%sxx' % i
            metric = 'haproxy_backend_response_' + response_code
            metric_desc = ' '.join([service, response_code])
            query_string = self._compile_query(
                measurement=metric,
                select=aggregates,
                where=("backend = '%s'" % service,),
                gb_period='1h', gb_tag='hostname')
            query = self._query(query_string)

            # Taking min from two
            for q in query:
                values = q['values']
                for value in values:
                    value[1] = min(value[1], value[2])
                    value.pop(-1)

            # Summing hosts
            temp_values = []
            for q in query:
                values = q['values']
                for i, v in enumerate(values):
                    if len(temp_values) < i + 1:
                        temp_values.append(v)
                    else:
                        temp_values[i][1] += v[1]

            temp_res = [{'values': temp_values}]
            res = self._process_query(
                temp_res, (key_desc,),
                metric=metric_desc,
                gb_time=True)
            # workaround for reseted counter

            for t, d in res.items():
                result.setdefault(t, {})
                result[t].update(d)

        def _swap_keys(dct):
            res = {}
            for t, d in dct.items():
                for m, v in d.items():
                    res.setdefault(m, {})
                    res[m].setdefault(t, {})
                    res[m][t] = v
            return res

        if self.status_codes:
            return _swap_keys(result)

        # sum different status codes responses
        res = {}
        for t, d in result.items():
            res.setdefault(t, {})
            res[t].update({service+' request number': sum(d.values())})
        return _swap_keys(res)

    def _compile_query(self, measurement, select, where=None, gb_tag=None,
                       gb_period=None):
        if isinstance(select, tuple):
            select = ", ".join(["%s(%s)" % (a, v) for a, v in select])
        query = "SELECT %s FROM %s WHERE " % (select, measurement)
        if where:
            for w in where:
                query += w + " AND "
        query += (
            "time >= '%(period_start)s'"
            " AND time < '%(period_end)s'"
        ) % self.__dict__
        gb_period = gb_period or self.gb_period
        query += " GROUP BY time(%s)" % gb_period
        if gb_tag:
            query += ",%s" % gb_tag
        query += " fill(0)"
        return query


def _adapt_format(t):
    if not t:
        return
    return t if t.endswith('Z') else t + 'Z'


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


#def write_cvs_report(report):
#
#    reports_dir = os.path.join(os.getcwd(), 'reports')
#    if not os.path.isdir(reports_dir):
#        os.mkdir(reports_dir)
#    report_dirs_list = [d for d in os.listdir(reports_dir)
#                        if d.startswith('report-')]
#    if report_dirs_list:
#        dir_idx = max([
#            int(d.split('-')[1])
#            for d in report_dirs_list]) + 1
#    else:
#        dir_idx = 1
#    report_base_dir = os.path.join(reports_dir, 'report-%s' % dir_idx)
#    os.mkdir(report_base_dir)
#    for report_name, report_data in report.items():
#       with open('%s.csv' % report_name, 'wb') as f:
#           writer = csv.writer(f)
#           sorted_columns = sorted(report_data.values()[0].keys())
#           writer.writerow([''] + sorted_columns)
#           for key in sorted(report_data.keys()):
#               value = report_data[key]
#               row = [key]
#               if sorted_columns:
#                   for column in sorted_columns:
#                       row.append(value[column])
#               else:
#                   row.append(value)
#               writer.writerow(row)


def write_cvs_report(report, start_time, end_time):
    interval = '%s - %s' % (start_time, end_time)
    reports_dir = os.path.join(os.getcwd(), 'reports')
    if not os.path.isdir(reports_dir):
        os.mkdir(reports_dir)
    report_files_list = [os.path.splitext(f)[0] for f in os.listdir(reports_dir)
                         if f.startswith('report-')]
    if report_files_list:
        file_idx = max([
            int(f.split('-')[1])
            for f in report_files_list]) + 1
    else:
        file_idx = 1
    report_file_path = os.path.join(reports_dir, 'report-%s.csv' % file_idx)
    with open(report_file_path, 'wb') as f:
        writer = csv.writer(f)
        for report_name, report_data in report.items():
           descr = report_name[1]

           time = end_time
           if 'period' in descr:
               time = interval
           f.write("%s %s\n" % (descr, time))

           sorted_columns = sorted(report_data.values()[0].keys())
           writer.writerow([''] + sorted_columns)
           for key in sorted(report_data.keys()):
               value = report_data[key]
               row = [key]
               if sorted_columns:
                   for column in sorted_columns:
                       v = value[column]
                       if isinstance(v, float):
                           v = round(v, 2)
                       row.append(v)
               else:
                   row.append(value)
               writer.writerow(row)
           f.write('\n')
    return report_file_path


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

    start_time, end_time = _calculate_time_borders(
        args.period_start, args.period_end, args.period)
    reports = {}
    for report_type in report_types:
        r = report_types_map[report_type](
            start_time=start_time,
            end_time=end_time,
            **args.__dict__)
        reports.update(r.get_reports())
    pprint.pprint(reports)
    print write_cvs_report(reports, start_time, end_time)


if __name__ == "__main__":
    main()

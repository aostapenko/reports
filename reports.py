#!/usr/bin/python2.7
import argparse
from datetime import datetime
import logging
import os
import pprint
import sys
import time

from influxdb import InfluxDBClient
from keystoneauth1 import discover
from keystoneauth1.identity import v2
from keystoneauth1.identity import v3
from keystoneauth1 import session
from novaclient import client as nova_client


logger = logging.getLogger(__file__)
logging.basicConfig()
logger.setLevel(logging.INFO)

TIME_FORMAT_MILLISEC = "%Y-%m-%dT%H:%M:%S.%fZ"
TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
CHUNK_SIZE = 1000


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
                                           "atp"),
                    help="InfluxDB username. Must have have READ rights for "
                         "lma and ceilometer dbs and ALL rights for "
                         "destination db.")
parser.add_argument("--influxdb_password",
                    default=os.environ.get("INFLUXDB_PASSWORD",
                                           "uHWYXdyiGgFEFS6pg8mzB1gv"),
                    help="InfluxDB password")
parser.add_argument("--influxdb_lma_dbname",
                    default=os.environ.get("INFLUXDB_LMA_DB_NAME",
                                           "lma"),
                    help="InfluxDB lma database name")
parser.add_argument("--influxdb_ceilometer_dbname",
                    default=os.environ.get("INFLUXDB_CEILOMETER_DB_NAME",
                                           "ceilometer"),
                    help="InfluxDB ceilometer database name")
parser.add_argument("--influxdb_dest_dbname",
                    default=os.environ.get("INFLUXDB_DEST_DB_NAME",
                                           "atp"),
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


class DataProcessorBase(object):

    @cut_arg_names('influxdb_')
    def _get_influx_client(self, host, port, username, password,
                           dbname, **kwargs):
        return InfluxDBClient(host, port, username, password, dbname)

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
        self.nova = nova_client.Client(
            2, session=sess, endpoint_type=endpoint_type)

    def _query_source(self, query):
        return self.source_db_client.query(query=query).raw.get('series', [])

    def _query_dest(self, query):
        return self.dest_db_client.query(query=query).raw.get('series', [])

    def _write_points(self, data):
        return self.dest_db_client.write_points(data, time_precision='ms')

    def _compile_query(self, measurement, select, where=(), gb_tags=(),
                       gb_period='1000y', start_time=None):
        if isinstance(select, tuple):
            select = ", ".join(["%s(%s)" % (a, v) for a, v in select])
        query = "SELECT %s FROM %s " % (select, measurement)

        if start_time:
            where = list(where)
            where.append("time >= '%s' - 2m" % start_time)
        if where:
            query += "WHERE "
            query += " AND ".join(where)

        if gb_period:
           gb_tags = list(gb_tags)
           gb_tags.append("time(%s)" % gb_period)
        if gb_tags:
            query += " GROUP BY "
            query += ",".join(gb_tags)
            query += " fill(0)"
        return query

    def _dest_measurement_last_date(self, measurement):
        query_string = self._compile_query(measurement, select='last(value)',
                                           gb_period=None)
        query = self._query_dest(query_string)
        if not query:
            return None
        return query[0]['values'][0][0]

    def store_data(self, data):
        def _sort_key(p):
            t = p['time']
            try:
                return datetime.strptime(t, TIME_FORMAT_MILLISEC)
            except ValueError:
                return datetime.strptime(t, TIME_FORMAT)

        data.sort(key=_sort_key)

        for i in xrange(0, len(data), CHUNK_SIZE):
            self._write_points(data[i:i + CHUNK_SIZE])
            time.sleep(0.2)

    def process(self):
        start_time = self._dest_measurement_last_date(self.DEST_MEASUREMENT)
        data = self.prepare_data(start_time)
        self.store_data(data)


class RequestsDataProcessor(DataProcessorBase):
    DEST_MEASUREMENT = 'atp_haproxy_backend_responses'

    def __init__(self, **kwargs):
        super(RequestsDataProcessor, self).__init__()
        self.source_db_client = self._get_influx_client(
            dbname=kwargs['influxdb_lma_dbname'], **kwargs)
        self.dest_db_client = self._get_influx_client(
            dbname=kwargs['influxdb_dest_dbname'], **kwargs)

    def prepare_data(self, start_time):
        result = {}
        # These metrics are counters by each haproxy node that reset unpredictably
        data = []
        select = 'difference(value)'
        for i in range(1, 6):
            response_code = '%sxx' % i
            measurement = 'haproxy_backend_response_' + response_code
            query_string = self._compile_query(
                measurement=measurement,
                select=select,
                start_time=start_time,
                gb_tags=('hostname', 'backend'),
                gb_period=None)
            query = self._query_source(query_string)

            for element in query:
                common_point_data = {
                    "measurement": self.DEST_MEASUREMENT,
                    "tags": {
                        "hostname": element['tags']['hostname'],
                        "backend": element['tags']['backend'],
                        "response_code": response_code,
                    }
                }
                for value in element['values']:
                    if value[1] <= 0:
                        continue
                    point = {"time": value[0],
                             "fields": {'value': value[1]}}
                    point.update(common_point_data)
                    data.append(point)

        return data


class InstanceDataProcessor(DataProcessorBase):
    DEST_MEASUREMENT = 'atp_instance'

    def __init__(self, **kwargs):
        super(InstanceDataProcessor, self).__init__()
        self.source_db_client = self._get_influx_client(
            dbname=kwargs['influxdb_ceilometer_dbname'], **kwargs)
        self.dest_db_client = self._get_influx_client(
            dbname=kwargs['influxdb_dest_dbname'], **kwargs)
        self._init_os_clients(**kwargs)
        self._image_names = {}

    def _get_image_name(self, uuid):
        if uuid not in self._image_names:
            try:
                image_name = self.nova.images.get(uuid).name
            except Exception:
                image_name = None
            self._image_names[uuid] = image_name
        return self._image_names[uuid]

    def _get_instance_image(self, uuid):
        search_opts = {
            'all_tenants': True,
            'uuid': uuid,
        }
        instance_list = self.nova.servers.list(search_opts=search_opts)
        if not instance_list:
            search_opts['deleted'] = True
            instance_list = self.nova.servers.list(search_opts=search_opts)
        image = instance_list[0].image
        if isinstance(image, dict):
            image_id = image['id']
            return self._get_image_name(image_id) or image_id
        else:
            return 'Not from image'

    def prepare_data(self, start_time):
        measurement = 'sample'
        select = 'value'
        where = (
            "meter = 'instance'",
            "metadata.instance_host != ''",
            "metadata.state != 'deleted'",
        )
        gb_tags=(
            "metadata.instance_host",
            "metadata.status",
            "metadata.instance_type",
            "resource_id",
        )
        query_string = self._compile_query(
            measurement=measurement,
            select=select,
            where=where,
            start_time=start_time,
            gb_tags=gb_tags,
            gb_period=None)
        query = self._query_source(query_string)

        def _round(t):
            temp = t[0:-1].split('.')
            if len(temp) < 2:
                return t
            m, f = temp
            return '.'.join([m, f[0:6]]) + 'Z'

        data = []
        for element in query:
            tags = element['tags']
            uuid = tags['resource_id']
            image = self._get_instance_image(uuid)
            common_point_data = {
                "measurement": self.DEST_MEASUREMENT,
                "tags": {
                    "hostname": tags['metadata.instance_host'],
                    "status": tags['metadata.status'],
                    "instance_type": tags['metadata.instance_type'],
                    "image": image,
                    "resource_id": uuid,
                }
            }
            for value in element['values']:
                point = {"time": _round(value[0]),
                         "fields": {'value': uuid}}
                point.update(common_point_data)
                data.append(point)
        return data


DATA_PROCESSORS = (
    InstanceDataProcessor,
    RequestsDataProcessor,
)


def main():
    args = parser.parse_args()
    for cls in DATA_PROCESSORS:
        data_processor = cls(**args.__dict__)
        data_processor.process()


if __name__ == "__main__":
    main()

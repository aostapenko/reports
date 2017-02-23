import argparse
import datetime
import os

from ceilometerclient import client as ceilometer_client
from keystoneauth1 import discover
from keystoneauth1.identity import v2
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client as keystone_client
from novaclient import client as nova_client


parser = argparse.ArgumentParser()

parser.add_argument("--project_id",
                    dest="project_id",
                    default=None,
                    help="Specify id of project, which statistics you "
                         "want to get")
parser.add_argument("--project-all",
                    default=False,
                    action="store_true",
                    dest="project_all",
                    help="Statistics of all cloud")
parser.add_argument("--username",
                    default=os.environ.get("OS_USERNAME", "admin"),
                    dest="username",
                    help="Name of the user")
parser.add_argument("--password",
                    default=os.environ.get("OS_PASSWORD", "admin"),
                    dest="password",
                    help="Password for the user")
parser.add_argument("--os_auth_url",
                    default=os.environ.get("OS_AUTH_URL",
                                           "http://localhost:5000"),
                    dest="os_auth_url",
                    help="Openstack authentification url")
parser.add_argument("--os_endpoint_type",
                    default=os.environ.get("OS_ENDPOINT_TYPE",
                                           "internalURL"),
                    dest="endpoint_type",
                    help="Endpoint type")
parser.add_argument("--admin_project_name",
                    default=os.environ.get("OS_PROJECT_NAME", "admin"),
                    dest="admin_project_name",
                    help="Name of admin project for auth")
parser.add_argument("--user_domain_id",
                    default=os.environ.get("OS_DEFAULT_DOMAIN", "default"),
                    dest="user_domain_id",
                    help="User domain id")
parser.add_argument("--project_domain_id",
                    default=os.environ.get("OS_DEFAULT_DOMAIN", "default"),
                    dest="project_domain_id",
                    help="Project domain id")
parser.add_argument("--period_start",
                    dest="period_start",
                    help="Time when period starts in format "
                         "<YYYY-MM-DDThh:mm:ss> e.g. 2017-01-12T00:00:00")
parser.add_argument("--period_end",
                    dest="period_end",
                    help="Time when period ends in format "
                         "<YYYY-MM-DDThh:mm:ss> e.g. 2017-01-13T00:00:00")


def _discover_auth_versions(session, auth_url):
    ks_discover = discover.Discover(session=session, url=auth_url)
    v2_auth_url = ks_discover.url_for('2.0')
    v3_auth_url = ks_discover.url_for('3.0')
    return v2_auth_url, v3_auth_url


class Reports(object):

    def __init__(self, username, password, auth_url, project_name,
                 user_domain_id=None, project_domain_id=None,
                 endpoint_type='publicURL'):
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

    def _get_query(self, period_start=None, period_end=None, project_id=None):
        query = []
        if period_start:
            query.append(dict(field="timestamp", op="gt", value=period_start))
        if period_end:
            query.append(dict(field="timestamp", op="lt", value=period_end))
        if project_id:
            query.append(dict(field="project", op="eq", value=project_id))
        return query

    def _get_resource_ids(self, meter, query):
        statistics = self.cclient.statistics.list(meter, q=query,
                                                  groupby='resource_id')
        return [entry.groupby['resource_id'] for entry in statistics]

    def _host_instances_count_old(self, **query_kwargs):
        query = self._get_query(**query_kwargs)
        query.append(dict(field="metadata.state", op="eq", value="active"))
        instance_ids = self._get_resource_ids('instance', query)
        host_instances_count = {}
        for instance_id in instance_ids:
            resource_query = [dict(field="resource_id", op="eq",
                                   value=instance_id)]
            samples = self.cclient.samples.list(
                'instance', q=query+resource_query, limit=1)
            instance_host = (
                samples[0].resource_metadata.get('instance_host') or
                samples[0].resource_metadata.get('host'
                    ).replace('compute.', '')
            )
            host_instances_count.setdefault(instance_host, 0)
            host_instances_count[instance_host] += 1
        return host_instances_count

    # considers migration case
    def _host_instances_count(self, **query_kwargs):
        query = self._get_query(**query_kwargs)
        query.append(dict(field="metadata.state", op="eq", value="active"))
        hypervisors = self.nova.hypervisors.list()
        host_instances_count = {}
        for hypervisor in hypervisors:
            host = hypervisor.hypervisor_hostname
            # host???
            host_query = [dict(field="metadata.instance_host", op="eq",
                               value=host)]
            statistics = self.cclient.statistics.list(
                'instance', q=query+host_query, groupby='resource_id')
            host_instances_count[host] = len(statistics)
        return host_instances_count


    def get_reports(self, **query_kwargs):
        print self._host_instances_count_old(**query_kwargs)
        print self._host_instances_count(**query_kwargs)


def main():
    args = parser.parse_args()

    r = Reports(args.username, args.password, args.os_auth_url,
                args.admin_project_name, args.user_domain_id,
                args.project_domain_id, args.endpoint_type)

    result = r.get_reports(project_id=args.project_id,
                           period_start=args.period_start,
                           period_end=args.period_end)



if __name__ == "__main__":
    main()

from openstack import connection
import os


def get_connection():
    return connection.Connection(
        auth_url=os.environ["OS_AUTH_URL"],
        project_name=os.environ["OS_PROJECT_NAME"],
        username=os.environ["OS_USERNAME"],
        password=os.environ["OS_PASSWORD"],
        user_domain_name=os.environ.get("OS_USER_DOMAIN_NAME", "Default"),
        project_domain_name=os.environ.get("OS_PROJECT_DOMAIN_NAME", "Default"),
        region_name=os.environ.get("OS_REGION_NAME", "RegionOne"),
        interface=os.environ.get("OS_INTERFACE", "public"),
        identity_api_version=os.environ.get("OS_IDENTITY_API_VERSION", "3"),
    )

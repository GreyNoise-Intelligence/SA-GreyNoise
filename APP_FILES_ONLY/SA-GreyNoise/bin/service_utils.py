"""
service_utils.py.

Helper file to create service object
"""
import socket

import app_greynoise_declare

import splunk.clilib.cli_common
import splunklib.client as client
import splunk.admin as admin

APP_NAME = app_greynoise_declare.ta_name


class GetSessionKey(admin.MConfigHandler):
    """Class to get session key."""

    def __init__(self):
        """Initialize session key."""
        self.session_key = self.getSessionKey()


def resolve_host(hostname):
    """Resolve hostname to IPv4/IPv6 address."""
    try:
        # This returns a list of (family, type, proto, canonname, sockaddr) tuples
        infos = socket.getaddrinfo(hostname, None)

        # Filter for IPv4 and IPv6 addresses
        ipv4_addresses = [info for info in infos if info[0] == socket.AF_INET]
        ipv6_addresses = [info for info in infos if info[0] == socket.AF_INET6]

        # Prefer IPv4, but fallback to IPv6 if necessary
        if ipv4_addresses:
            address = ipv4_addresses[0][4][0]
        elif ipv6_addresses:
            address = ipv6_addresses[0][4][0]
        else:
            return None  # No suitable address found
        return address
    except socket.gaierror:
        return None


def create_service(sessionkey=None, owner=None, autologin=True):
    """Create Service to communicate with splunk."""
    mgmt_uri = splunk.clilib.cli_common.getMgmtUri()
    hostname = mgmt_uri.split("//")[-1].split(":")[0]  # Extract hostname from URI
    mgmt_port = mgmt_uri.split(":")[-1]
    service = None

    # Resolve hostname to IPv4 address
    ip_address = resolve_host(hostname)
    if not ip_address:
        raise Exception("Failed to resolve Splunk management URI to an IP address.")

    if not sessionkey:
        sessionkey = GetSessionKey().session_key

    if owner:
        service = client.connect(
            host=ip_address,
            port=mgmt_port,
            token=sessionkey,
            app=APP_NAME,
            owner=owner,
            autologin=autologin
        )
    else:
        service = client.connect(host=ip_address, port=mgmt_port, token=sessionkey, app=APP_NAME)

    return service

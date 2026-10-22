import ipaddress
import requests


def lookup_ip(ip: str) -> dict:
    """
    Look up public IP infrastructure information.
    This does not identify the physical location of a person.
    """

    try:
        address = ipaddress.ip_address(ip)

        if (
            address.is_private
            or address.is_loopback
            or address.is_reserved
        ):
            return {
                "ip": ip,
                "status": "private_or_reserved",
                "message": "Not a public Internet IP."
            }

    except ValueError:
        return {
            "ip": ip,
            "status": "invalid",
            "message": "Invalid IP address."
        }

    try:
        response = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=10
        )

        response.raise_for_status()
        data = response.json()

        if not data.get("success", False):
            return {
                "ip": ip,
                "status": "not_found"
            }

        connection = data.get("connection", {})
        timezone = data.get("timezone", {})

        return {
            "ip": ip,
            "status": "success",
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "asn": connection.get("asn"),
            "organization": connection.get("org"),
            "isp": connection.get("isp"),
            "domain": connection.get("domain"),
            "timezone": timezone.get("id"),
        }

    except requests.RequestException as error:
        return {
            "ip": ip,
            "status": "error",
            "message": str(error)
        }

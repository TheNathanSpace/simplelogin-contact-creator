import logging
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class TZFormatter(logging.Formatter):
    def __init__(self, zone):
        super().__init__("%(asctime)s %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
        self.zone = zone

    def formatTime(self, record, datefmt=None):
        moment = datetime.fromtimestamp(record.created, self.zone)
        return moment.strftime(datefmt or self.datefmt)


def configure_logging(tz_name):
    try:
        zone = ZoneInfo(tz_name)
        used = tz_name
    except ZoneInfoNotFoundError:
        zone = ZoneInfo("Etc/UTC")
        used = "Etc/UTC"
    handler = logging.StreamHandler()
    handler.setFormatter(TZFormatter(zone))
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    if used != tz_name:
        logging.getLogger("adapter").warning(
            "timezone %s is not a valid IANA name; using Etc/UTC", tz_name
        )
    return used


def one_line(value, limit=200):
    text = str(value).replace("\r", " ").replace("\n", " ")
    if len(text) > limit:
        return text[:limit]
    return text

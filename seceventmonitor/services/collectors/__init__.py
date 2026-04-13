from seceventmonitor.services.collectors.base import BaseCollector
from seceventmonitor.services.collectors.chaitin import ChaitinCollector
from seceventmonitor.services.collectors.cnnvd import CnnvdCollector
from seceventmonitor.services.collectors.kev import KevCollector
from seceventmonitor.services.collectors.nvd import NvdCollector
from seceventmonitor.services.collectors.oscs import OscsCollector
from seceventmonitor.services.collectors.qianxin_ti import QianxinTiCollector
from seceventmonitor.services.collectors.seebug import SeebugCollector
from seceventmonitor.services.collectors.threatbook import ThreatBookCollector
from seceventmonitor.services.collectors.venustech import VenustechCollector

COLLECTOR_MAP = {
    "nvd": NvdCollector,
    "cnnvd": CnnvdCollector,
    "chaitin": ChaitinCollector,
    "oscs": OscsCollector,
    "qianxin_ti": QianxinTiCollector,
    "threatbook": ThreatBookCollector,
    "seebug": SeebugCollector,
    "venustech": VenustechCollector,
    "kev": KevCollector,
}

SYNC_SOURCE_LABELS = {
    "nvd": "NVD",
    "cnnvd": "CNNVD",
    "chaitin": "长亭漏洞库",
    "oscs": "OSCS开源安全情报预警",
    "qianxin_ti": "奇安信威胁情报中心",
    "threatbook": "微步在线研究响应中心",
    "seebug": "Seebug漏洞库",
    "venustech": "启明星辰漏洞通告",
    "kev": "CISA KEV",
}


def list_sync_source_options():
    return [{"value": key, "label": label} for key, label in SYNC_SOURCE_LABELS.items()]


def list_supported_vulnerability_sources():
    return [label for key, label in SYNC_SOURCE_LABELS.items()]


__all__ = [
    "BaseCollector",
    "ChaitinCollector",
    "CnnvdCollector",
    "COLLECTOR_MAP",
    "KevCollector",
    "NvdCollector",
    "OscsCollector",
    "QianxinTiCollector",
    "SYNC_SOURCE_LABELS",
    "SeebugCollector",
    "ThreatBookCollector",
    "VenustechCollector",
    "list_supported_vulnerability_sources",
    "list_sync_source_options",
]

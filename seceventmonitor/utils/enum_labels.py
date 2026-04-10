SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "unknown": "未知",
}

STATUS_LABELS = {
    "new": "新增",
    "updated": "更新",
}

ENUM_VALUE_LABELS = {
    "vuln_status": {
        "RECEIVED": "已接收",
        "AWAITING ANALYSIS": "待分析",
        "UNDERGOING ANALYSIS": "分析中",
        "ANALYZED": "已分析",
        "MODIFIED": "已变更",
        "DEFERRED": "已延期",
        "REJECTED": "已拒绝",
    },
    "base_severity": {
        "NONE": "无",
        "LOW": "低危",
        "MEDIUM": "中危",
        "HIGH": "高危",
        "CRITICAL": "严重",
        "UNKNOWN": "未知",
    },
    "attack_vector": {
        "NETWORK": "网络",
        "ADJACENT": "邻接网络",
        "ADJACENT_NETWORK": "邻接网络",
        "LOCAL": "本地",
        "PHYSICAL": "物理",
    },
    "attack_complexity": {
        "LOW": "低",
        "HIGH": "高",
    },
    "attack_requirements": {
        "NONE": "无",
        "PRESENT": "存在",
    },
    "privileges_required": {
        "NONE": "无",
        "LOW": "低",
        "HIGH": "高",
    },
    "user_interaction": {
        "NONE": "无",
        "REQUIRED": "需要",
        "PASSIVE": "被动",
        "ACTIVE": "主动",
    },
    "scope": {
        "UNCHANGED": "未改变",
        "CHANGED": "已改变",
    },
    "confidentiality_impact": {
        "NONE": "无",
        "LOW": "低",
        "HIGH": "高",
    },
    "integrity_impact": {
        "NONE": "无",
        "LOW": "低",
        "HIGH": "高",
    },
    "availability_impact": {
        "NONE": "无",
        "LOW": "低",
        "HIGH": "高",
    },
}


def enum_label(field_name: str, value):
    if value in (None, ""):
        return "-"
    text = str(value).strip()
    mapping = ENUM_VALUE_LABELS.get(field_name, {})
    return mapping.get(text.upper(), text)

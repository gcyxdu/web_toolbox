"""Shared, explicit plugin metadata. Algorithms never load from browser strings."""
from __future__ import annotations

from backend.config.models import LAYERSIFT_LAYERS, LAYERSIFT_DIMENSIONS

ATTACKS = {
    "None": {"name": "无攻击", "description": "所有客户端按正常流程训练。", "fields": []},
    "Gaussian": {"name": "Gaussian", "description": "用高斯噪声替代恶意客户端上传的更新。", "fields": [
        {"key": "noise_mean", "label": "噪声均值", "default": 0.0, "min": -10, "max": 10, "step": 0.1},
        {"key": "noise_std", "label": "噪声标准差", "default": 0.3, "min": 0, "max": 10, "step": 0.05}]},
    "SignFlipping": {"name": "Sign flipping", "description": "对客户端上传的更新取负。", "fields": []},
    "BadNets": {"name": "BadNets", "description": "在部分本地样本右下角植入触发器，并改为目标标签。", "fields": [
        {"key": "poisoning_ratio", "label": "样本投毒比例", "default": 0.3, "min": 0, "max": 1, "step": 0.05},
        {"key": "target_label", "label": "目标类别", "default": 0, "min": 0, "max": 99, "step": 1},
        {"key": "trigger_size", "label": "触发器边长 / px", "default": 2, "min": 1, "max": 3, "step": 1}]},
}
DEFENSES = {
    "LayerSift": {
        "name": "LayerSift",
        "description": "固定层两阶段投影，以 Multi-Krum 筛选客户端，再聚合完整更新。当前为明文在线算法。",
        "models": list(LAYERSIFT_LAYERS),
        "presets": {name: [label for label, _ in layers] for name, layers in LAYERSIFT_LAYERS.items()},
        "projection_dimensions": LAYERSIFT_DIMENSIONS,
        "fields": [{"key": "byzantine_ratio", "label": "恶意比例上界", "default": 0.2,
                    "min": 0, "max": 0.45, "step": 0.05}],
    },
    "Mean": {"name": "Mean", "description": "对客户端更新等权平均。", "fields": []},
    "Median": {"name": "Coordinate median", "description": "逐坐标计算中位数，不生成恶意身份预测。", "fields": []},
    "TrimmedMean": {"name": "Trimmed mean", "description": "逐坐标去掉两端的极值再平均。", "fields": [
        {"key": "beta", "label": "单侧裁剪比例", "default": 0.1, "min": 0, "max": 0.45, "step": 0.05}]},
    "NormClipping": {"name": "Norm clipping", "description": "限制单个更新的 L2 范数，再等权聚合。", "fields": [
        {"key": "norm_threshold", "label": "L2 范数阈值", "default": 1.0, "min": 0.01, "max": 100, "step": 0.1}]},
    "Krum": {"name": "Krum", "description": "根据邻近更新的距离选择一个更新。", "fields": [
        {"key": "byzantine_budget", "label": "Byzantine 数量上界", "default": 1, "min": 0, "max": 18, "step": 1}]},
}


def defaults(kind: str, method: str) -> dict[str, float | int]:
    catalog = ATTACKS if kind == "attack" else DEFENSES
    return {f["key"]: f["default"] for f in catalog[method]["fields"]}


def validate_params(kind: str, method: str, params: dict) -> None:
    import math

    catalog = ATTACKS if kind == "attack" else DEFENSES
    fields = {f["key"]: f for f in catalog[method]["fields"]}
    for key, value in params.items():
        if key not in fields:
            raise ValueError(f"{method} 不支持参数 {key}")
        field = fields[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError(f"{key} 必须是有限数值")
        if not field["min"] <= value <= field["max"]:
            raise ValueError(f"{key} 必须在 {field['min']} 到 {field['max']} 之间")
        if field["step"] == 1 and int(value) != value:
            raise ValueError(f"{key} 必须为整数")

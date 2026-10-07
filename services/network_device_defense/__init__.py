"""Clasificación de dispositivos y control de defensa de red — extensión AIE/NDR."""
from services.network_device_defense.device_classifier import (
    NOVUSDeviceClassifier,
    classify_device_from_node,
)
from services.network_device_defense.defense_controller import (
    NOVUSDefenseController,
    get_defense_controller,
)

__all__ = [
    "NOVUSDeviceClassifier",
    "classify_device_from_node",
    "NOVUSDefenseController",
    "get_defense_controller",
]

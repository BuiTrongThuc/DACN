from attack_simulator.ui.tabs.tab_detections import build_detections_tab
from attack_simulator.ui.tabs.tab_overview import build_overview_tab
from attack_simulator.ui.tabs.tab_report import build_report_tab
from attack_simulator.ui.tabs.tab_ueba_atomic import build_ueba_atomic_tab
from attack_simulator.ui.tabs.tab_vm_guide import build_vm_guide_tab
from attack_simulator.ui.tabs.tab_xml_inspector import build_xml_inspector_tab

__all__ = [
    "build_overview_tab",
    "build_detections_tab",
    "build_xml_inspector_tab",
    "build_ueba_atomic_tab",
    "build_report_tab",
    "build_vm_guide_tab",
]

# -*- coding: utf-8 -*-
"""Chargement des modules du projet pour les tests (python3 -m unittest discover -s tests -t .)."""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COLLECTOR = os.path.join(ROOT, "roles", "cmdb_collect", "files", "cmdb_collector.py")
SHELL_COLLECTOR = os.path.join(ROOT, "roles", "cmdb_collect", "files", "cmdb_collector.sh")
TOOLS = os.path.join(ROOT, "tools")
sys.path.insert(0, TOOLS)


def load_collector():
    spec = importlib.util.spec_from_file_location("cmdb_collector_test", COLLECTOR)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


C = load_collector()

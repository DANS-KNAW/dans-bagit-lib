#
# Copyright (C) 2026 DANS - Data Archiving and Networked Services (info@dans.knaw.nl)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import subprocess
import xml.etree.ElementTree as ET
import re


def get_latest_version():
    try:
        tag = subprocess.check_output(
            ["git", "describe", "--tags", "--abbrev=0"],
            stderr=subprocess.DEVNULL,
            text=True
        ).strip()
        if tag:
            return tag[1:] if tag.startswith("v") else tag
    except Exception:
        pass

    try:
        git_tags = subprocess.check_output(
            ["git", "tag"],
            stderr=subprocess.DEVNULL,
            text=True
        ).splitlines()
        version_tags = [t for t in git_tags if re.match(r"^v?\d+\.\d+\.\d+", t.strip())]
        if version_tags:
            def parse_ver(t):
                m = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", t.strip())
                return tuple(map(int, m.groups())) if m else ()
            version_tags.sort(key=parse_ver)
            latest = version_tags[-1].strip()
            return latest[1:] if latest.startswith("v") else latest
    except Exception:
        pass

    try:
        tree = ET.parse("pom.xml")
        root = tree.getroot()
        ns = {"m": "http://maven.apache.org/POM/4.0.0"}
        version = root.findtext("m:version", namespaces=ns) or ""
        return version
    except Exception:
        return ""


def define_env(env):
    env.variables["project_version"] = get_latest_version()

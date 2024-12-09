# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import json
import os
import re
import unicodedata

from lib4package.metadata import Metadata
from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship
from lib4sbom.license import LicenseScanner


class JavascriptScanner:
    """
    Simple Javascript File Scanner.
    """

    DEFAULT_LICENCE = "NOASSERTION"
    DEFAULT_AUTHOR = "UNKNOWN"
    DEFAULT_PARENT = "-"
    VERSION_UNKNOWN = "NA"
    LOCK_FILE = "package-lock.json"

    def __init__(self, debug, ignore_missing_dependencies=True):
        self.record = []
        self.packages = []
        self.javascript_file = None
        self.module_data = {}
        self.debug = debug
        self.javascript_package = SBOMPackage()
        self.javascript_relationship = SBOMRelationship()
        self.sbom_document = SBOMDocument()
        self.javascript_packages = {}
        self.javascript_relationships = []
        self.license = LicenseScanner()
        self.package_metadata = Metadata("Javascript", debug=self.debug)
        self.lock_file = None
        self.ignore_missing_dependencies = ignore_missing_dependencies
        self.sbom_document.set_value("lifecycle", "build")
        self.sbom_document.set_metadata_type("application")
        self.application_name = None

    def set_dependency_file(self, dependency_directory):
        lock_file = self.LOCK_FILE
        self.dependency_file = os.path.join(dependency_directory, lock_file)
        self.module_valid = False
        if self.debug:
            print(f"Process {self.dependency_file}")
        if os.path.exists(self.dependency_file):
            # Load data from file
            with open(os.path.abspath(self.dependency_file), "r") as file_handle:
                self.module_data = json.load(file_handle)
            self.lock_file = self.dependency_file

    def _format_supplier(self, supplier_info, include_email=True):
        # See https://stackoverflow.com/questions/1207457/convert-a-unicode-string-to-a-string-in-python-containing-extra-symbols
        # And convert byte object to a string
        name_str = (
            unicodedata.normalize("NFKD", supplier_info)
            .encode("ascii", "ignore")
            .decode("utf-8")
        )
        if " " in name_str:
            # Get names assumed to be at least two names <first> <surname>
            names = re.findall(r"[a-zA-Z\.\]+ [A-Za-z]+ ", name_str)
        else:
            # Handle case where only single name provided
            names = [name_str]
        # Get email addresses
        if self.debug:
            print(f"{supplier_info} => {name_str} => {names}")
        # Use RFC-5322 compliant regex (https://regex101.com/library/6EL6YF)
        emails = re.findall(
            r"((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\]))",
            supplier_info,re.IGNORECASE
        )
        supplier = " ".join(n for n in names)
        if include_email and len(emails) > 0:
            # Only one email can be specified, so choose last one
            supplier = supplier + "(" + emails[-1] + ")"
        return re.sub(" +", " ", supplier.strip())

    def _dependencies(self, module, parent):
        for entry in module:
            # To handle @actions/<product>: lines, extract product name from line
            # product = entry.split("/")[1] if "/" in entry else entry
            product = entry
            try:
                version = module[entry]["version"]
            except Exception:
                # Cater for case when version field not present
                version = "UNKNOWN"
            if version != "UNKNOWN":
                self.packages.append([product, version])
                self.add_entry(parent, product, version)
            else:
                print(f"Version not found for {product}")
        for entry in module:
            # product = entry.split("/")[1] if "/" in entry else entry
            product = entry
            for x in module[entry]:
                if "dependencies" in x:
                    self._dependencies(module[entry]["dependencies"], product)
                if "requires" in x:
                    for dep in module[entry]["requires"]:
                        dep_version = self.VERSION_UNKNOWN
                        # dep_package = dep.split("/")[1] if "/" in dep else dep
                        dep_package = dep
                        package = self.get_package(dep_package)
                        if package is None:
                            if self.ignore_missing_dependencies:
                                # Need to add package
                                if self.debug:
                                    print(
                                        f"Dependent package {dep_package} not found. Adding dependency"
                                    )
                                dep_version = module[entry]["requires"][dep].replace(
                                    "^", ""
                                )
                            else:
                                if self.debug:
                                    print(
                                        f"Dependent package {dep_package} not defined"
                                    )
                                dep_package = None
                        else:
                            dep_version = package[2]
                        if dep_package is not None:
                            self.add_entry(product, dep_package, dep_version)

    def show_module(self):
        print(self.module_data)

    def process_dependency(self):
        # If file not found, no metadata to process
        if len(self.module_data) > 0:
            # Module name
            application = self.module_data["name"]
            version = self.module_data["version"]
            # self.packages.append([application, version])
            # self.sbom_document.set_name(application)
            self.application_name = application
            # self.sbom_document.set_metadata_version(version)
            self.add_entry(
                self.DEFAULT_PARENT, application, version, package_type="APPLICATION"
            )
            self.module_valid = True
            # Process all packages
            self._dependencies(self.module_data["dependencies"], application)
        elif self.debug:
            print(f"[ERROR] File {self.dependency_file} not found")

    def add(self, entry):
        if entry not in self.record:
            self.record.append(entry)

    def get_package(self, name, version=None):
        for package in self.record:
            if version is None and name == package[1]:
                return package
            elif name == package[1] and version == package[2]:
                return package
        return None

    def add_entry(self, parent, name, version, package_type="LIBRARY"):
        if self.debug:
            print(f"Add entry {parent} - {name} {version}")
        self.add(
            [
                parent,
                name,
                version,
                self.DEFAULT_AUTHOR,
                self.DEFAULT_LICENCE,
            ]
        )
        p = (name, version)
        # if package_type != "APPLICATION" and p not in self.javascript_packages:
        if p not in self.javascript_packages:
            self.javascript_package.initialise()
            self.javascript_package.set_name(name)
            self.javascript_package.set_version(version)
            self.javascript_package.set_property("language", "Javascript")
            self.javascript_package.set_type(package_type)
            self.javascript_package.set_evidence(self.lock_file)
            # Enrich package data
            self.package_metadata.get_package(name, version=version)
            self.javascript_package.set_value(
                "release_date", self.package_metadata.get_latest_release_time()
            )
            if self.debug:
                self.package_metadata.print_data()
            # Checksum may be in file (SHA512)
            checksum, checksum_algorithm = self.package_metadata.get_checksum(version=version)
            originator = self.package_metadata.get_originator()
            description = self.package_metadata.get_description()
            package_licence = self.package_metadata.get_license()
            homepage = self.package_metadata.get_homepage()
            download_location = self.package_metadata.get_downloadlocation()
            self.javascript_package.set_filesanalysis(False)
            # Assume supplier not known
            self.javascript_package.set_supplier("UNKNOWN", "NOASSERTION")
            if originator is not None:
                if len(originator.split()) > 3:
                    self.javascript_package.set_supplier(
                        "Organization", self._format_supplier(originator)
                    )
                elif len(originator) > 1:
                    if self.debug:
                        print(f"{originator} => {self._format_supplier(originator)}")
                    self.javascript_package.set_supplier(
                        "Person", self._format_supplier(originator)
                    )
            if package_licence is not None:
                license = self.license.find_license(package_licence)
                if self.debug:
                    print(f"{package_licence} => {license}")
                # Report license as reported by metadata. If not valid SPDX, report NOASSERTION
                if license != package_licence:
                    self.javascript_package.set_licensedeclared("NOASSERTION")
                else:
                    self.javascript_package.set_licensedeclared(license)
                # Report license if valid SPDX identifier
                self.javascript_package.set_licenseconcluded(license)
                # Add comment if metadata license was modified
                license_comment = ""
                if len(package_licence) > 0 and license != package_licence:
                    license_comment = f"{name} declares {package_licence} which is not currently a valid SPDX License identifier or expression."
                # Report if license is deprecated
                if self.license.deprecated(license):
                    deprecated_comment = f"{license} is now deprecated."
                    if len(license_comment) > 0:
                        license_comment = f"{license_comment} {deprecated_comment}"
                    else:
                        license_comment = deprecated_comment
                if len(license_comment) > 0:
                    self.javascript_package.set_licensecomments(license_comment)
            else:
                self.javascript_package.set_licenseconcluded(self.DEFAULT_LICENCE)
                self.javascript_package.set_licensedeclared(self.DEFAULT_LICENCE)
            if checksum is not None:
                self.javascript_package.set_checksum(checksum_algorithm, checksum)
            if homepage is not None:
                self.javascript_package.set_homepage(homepage)
            if download_location is not None:
                self.javascript_package.set_downloadlocation(download_location)
            if description is not None:
                self.javascript_package.set_summary(description)
            self.javascript_package.set_externalreference(
                "PACKAGE-MANAGER", "purl", f"pkg:npm/{name}@{version}"
            )
            # Copyright
            self.javascript_package.set_copyrighttext("NOASSERTION")
            self.javascript_packages[(name, version)] = (
                self.javascript_package.get_package()
            )
        # Record relationship
        if parent != self.DEFAULT_PARENT:
            if self.debug:
                print(f"Add relationship {parent} DEPENDS ON {name}")
            self.javascript_relationship.initialise()
            self.javascript_relationship.set_relationship(parent, "DEPENDS_ON", name)
            self.javascript_relationships.append(
                self.javascript_relationship.get_relationship()
            )
        else:
            if self.debug:
                print(f"Add relationship {parent} DESCRIBES {name}")
            self.javascript_relationship.initialise()
            self.javascript_relationship.set_relationship(
                self.application_name, "DESCRIBES", name
            )
            self.javascript_relationships.append(
                self.javascript_relationship.get_relationship()
            )

    def get_record(self):
        return self.record

    def get_packages(self):
        return self.javascript_packages

    def get_relationships(self):
        return self.javascript_relationships

    def get_document(self):
        return self.sbom_document.get_document()

    def get_application_name(self):
        return self.application_name

    def get_lock_file(self):
        return self.lock_file

    def valid_module(self):
        return self.module_valid

    def show_record(self):
        for r in self.record:
            print(r)

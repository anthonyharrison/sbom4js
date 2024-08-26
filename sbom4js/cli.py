# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import sys
import textwrap
from collections import ChainMap

from lib4sbom.generator import SBOMGenerator
from lib4sbom.sbom import SBOM

from sbom4js.scanner import JavascriptScanner
from sbom4js.version import VERSION

# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    app_name = "sbom4js"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            SBOM4JS generates a Software Bill of Materials for
            a Javascript application identifying all of the dependent components.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-d",
        "--dependency",
        action="store",
        default="",
        help="Directory containing javascript dependency file",
    )

    input_group.add_argument(
        "--ignore",
        action="store_true",
        default=False,
        help="ignore missing dependencies",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )
    output_group.add_argument(
        "--sbom",
        action="store",
        default="spdx",
        choices=["spdx", "cyclonedx"],
        help="specify type of sbom to generate (default: spdx)",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="tag",
        choices=["tag", "json", "yaml"],
        help="format for SPDX software bill of materials (sbom) (default: tag)",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "dependency": "",
        "exclude_license": False,
        "output_file": "",
        "sbom": "spdx",
        "debug": False,
        "format": "tag",
        "ignore": False,
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    dependency_location = args["dependency"]

    if dependency_location == "":
        # Assume current directory
        dependency_location = os.getcwd()

    if args["sbom"] == "spdx":
        bom_format = args["format"]
    else:
        bom_format = "json"

    if args["debug"]:
        print("SBOM type", args["sbom"])
        if args["sbom"] == "spdx":
            print("Format", bom_format)
        print("Output file", args["output_file"])
        print("Directory", dependency_location)
        print("Ignore Missing Dependencies", args["ignore"])

    sbom_scan = JavascriptScanner(args["debug"], args["ignore"])
    sbom_scan.set_dependency_file(dependency_location)
    sbom_scan.process_dependency()

    if args["debug"]:
        print("Valid module", sbom_scan.valid_module())
        sbom_scan.show_record()
        print(sbom_scan.get_relationships())

    # If file not found, abort processing
    if not sbom_scan.valid_module():
        return -1

    # Generate SBOM file

    javascript_sbom = SBOM()
    javascript_sbom.add_document(sbom_scan.get_document())
    javascript_sbom.add_packages(sbom_scan.get_packages())
    javascript_sbom.add_relationships(sbom_scan.get_relationships())
    javascript_sbom.set_property("language", "Javascript")

    sbom_gen = SBOMGenerator(
        sbom_type=args["sbom"], format=bom_format, application=app_name, version=VERSION
    )
    sbom_gen.generate(
        project_name=f"JS-{sbom_scan.get_application_name()}",
        sbom_data=javascript_sbom.get_sbom(),
        filename=args["output_file"],
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())

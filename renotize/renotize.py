### System ###
import os
import re
import sys
import time
import json
import shutil
import logging
import textwrap
from glob import glob
from subprocess import Popen, PIPE, STDOUT
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED

### Logging ###
from rich.logging import RichHandler

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, markup=True)],
)

logger = logging.getLogger("rich")

### Parsing ###
import yaml
import arrow

### CLI Parsing ###
import click

### Display ###
from tqdm import tqdm


uid_pattern = r"RequestUUID = ([A-z0-9-]+)"
status_pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \+\d{4}) ([A-z0-9-]+) (success|invalid|in progress)(?: (\d)\s+(Package (?:Approved|Invalid)))?"  # noqa: E501


class PermZipFile(ZipFile):
    def extract(self, member, path=None, pwd=None):
        if not isinstance(member, ZipInfo):
            member = self.getinfo(member)

        if path is None:
            path = os.getcwd()

        ret_val = self._extract_member(member, path, pwd)
        attr = member.external_attr >> 16
        os.chmod(ret_val, attr)

        return ret_val


class AliasedGroup(click.Group):
    def get_command(self, ctx, cmd_name):
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        matches = [x for x in self.list_commands(ctx) if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail("Too many matches: {}".format(", ".join(sorted(matches))))


def get_members_zip(zip):
    parts = []
    for name in zip.namelist():
        if not name.endswith("/"):
            data = name.split("/")[:-1]
            if data:
                parts.append(data)
    prefix = os.path.commonprefix(parts)
    if prefix:
        prefix = "/".join(prefix) + "/"
    offset = len(prefix)
    for zipinfo in zip.infolist():
        name = zipinfo.filename
        if len(name) > offset:
            zipinfo.filename = name[offset:]
            yield zipinfo


def zipdir(zipname, dirname):
    total = 0
    for root, dirs, files in os.walk(dirname):
        for fname in files:
            path = os.path.join(root, fname)
            total += os.path.getsize(path)

    z = PermZipFile(zipname, "w", ZIP_DEFLATED)

    current = 0
    with tqdm(total=total, unit_scale=True, unit="B") as pbar:
        for root, dirs, files in os.walk(dirname):
            for fname in files:
                path = os.path.join(root, fname)
                size = os.path.getsize(path)
                pbar.update(size)
                z.write(path)
                current += size
    z.close()


@click.group(cls=AliasedGroup)
@click.pass_context
@click.argument(
    "project",
    required=True,
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
)
@click.option(
    "-c",
    "--config",
    required=True,
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
)
@click.option("-d", "--debug", is_flag=True, help="Print debug information if given")
def cli(ctx, project, config, debug):
    """A utility script for quickly and automatically notarizing Ren'Py applications for macOS.

    Commands can be abbreviated by the shortest unique string.

    \b
    For example:
        unpack-app -> u
        sign-app -> sign-a
        sign-dmg -> sign-d

    \b
    The fully automatic process can be started using:
        renotize -c <path_to_config> <path_to_ZIP_file> full-run
    """
    ctx.ensure_object(dict)

    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    ctx.obj["debug"] = debug

    if not project.endswith(".zip"):
        project += ".zip"

    ctx.obj["project"] = os.path.splitext(project)[0]

    with open(config, "r") as f:
        ctx.obj["config"] = yaml.full_load(f)

    if not ctx.obj["config"]["altool_extra"]:
        ctx.obj["config"]["altool_extra"] = ""


@cli.command()
@click.pass_context
def unpack_app(ctx):
    logger.info("Unpacking App")
    zip_file = ctx.obj["project"] + ".zip"
    folder_name = ctx.obj["project"]

    if os.path.isdir(folder_name):
        logger.error(
            "Directory '{}' already exists, please remove it.".format(folder_name)
        )
        sys.exit(1)

    with PermZipFile(zip_file, "r") as f:
        for member in tqdm(f.infolist()):
            f.extract(member, folder_name)


@cli.command()
@click.pass_context
def sign_app(ctx):
    logger.info("Signing App")
    with open("entitlements.plist", "w") as f:
        f.write(
            textwrap.dedent(
                """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
                <dict>
                    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
                    <true/>
                </dict>
            </plist>"""
            )
        )

    app_path = sorted(glob(os.path.join(ctx.obj["project"], "*.app")))[0]

    cmd = [
        "codesign",
        "--entitlements=entitlements.plist",
        "--options=runtime",
        "--timestamp",
        "-s '{}'".format(ctx.obj["config"]["identity"]),
        "-f",
        "--deep",
        "--no-strict",
        app_path,
    ]
    if ctx.obj["debug"]:
        cmd.append("--verbose")
    cmd = " ".join(cmd)

    logger.info("Running codesign")
    proc = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
    for line in proc.stdout:
        logger.debug(str(line.strip(), "utf-8"))

    if proc.returncode:
        logger.error(
            "An error occured while signing the app, run with --debug for more details."
        )
        sys.exit(1)


@cli.command()
@click.pass_context
def notarize_app(ctx):
    logger.info("Notarizing App")
    zip_file = "{}-app.zip".format(ctx.obj["project"])

    app_path = sorted(glob(os.path.join(ctx.obj["project"], "*.app")))[0]

    zipdir(zip_file, app_path)

    cmd = [
        "xcrun",
        "altool",
        ctx.obj["config"]["altool_extra"],
        "-u {}".format(ctx.obj["config"]["apple_id"]),
        "-p {}".format(ctx.obj["config"]["password"]),
        "--notarize-app",
        "--primary-bundle-id {}".format(ctx.obj["config"]["bundle"]),
        "-f",
        zip_file,
    ]
    if ctx.obj["debug"]:
        cmd.append("--verbose")
    cmd = " ".join(cmd)

    logger.info("Running altool")
    uid = None
    proc = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
    for line in proc.stdout:
        line = str(line.strip(), "utf-8")
        logger.debug(line)
        m = re.match(uid_pattern, line)
        if m:
            uid = m.group(1)

    if proc.returncode:
        logger.error(
            "An error occured while notarizing the app, run with --debug for more details."
        )
        sys.exit(1)

    logger.info("The app was submitted. The UID is: {}".format(uid))

    return uid


@cli.command()
@click.pass_context
def staple_app(ctx):
    logger.info("Stapling App")
    app_path = sorted(glob(os.path.join(ctx.obj["project"], "*.app")))[0]

    cmd = ["xcrun", "stapler", "staple", app_path]
    cmd = " ".join(cmd)

    logger.info("Running stapler")
    proc = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
    for line in proc.stdout:
        logger.debug(str(line.strip(), "utf-8"))

    if proc.returncode:
        logger.error(
            "An error occured while stapling the notarization ticket to the app, run with --debug for more details."
        )
        sys.exit(1)


@cli.command()
@click.pass_context
def pack_dmg(ctx):
    logger.info("Packing DMG")
    cmd = [
        "hdiutil",
        "create",
        "-fs HFS+",
        "-format UDBZ",
        "-ov",
        "-volname {}".format(os.path.basename(ctx.obj["project"])),
        "-srcfolder {}".format(ctx.obj["project"]),
        "{}.dmg".format(ctx.obj["project"]),
    ]
    cmd = " ".join(cmd)

    logger.info("Running hdiutil")
    proc = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
    for line in proc.stdout:
        logger.debug(str(line.strip(), "utf-8"))

    if proc.returncode:
        logger.error(
            "An error occured while packing the DMG, run with --debug for more details."
        )
        sys.exit(1)


@cli.command()
@click.pass_context
def sign_dmg(ctx):
    logger.info("Signing DMG")
    cmd = [
        "codesign",
        "--timestamp",
        "-s {}".format(ctx.obj["config"]["identity"]),
        "-f {}.dmg".format(ctx.obj["project"]),
    ]
    if ctx.obj["debug"]:
        cmd.append("--verbose")
    cmd = " ".join(cmd)

    logger.info("Running codesign")
    proc = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
    for line in proc.stdout:
        logger.debug(str(line.strip(), "utf-8"))

    if proc.returncode:
        logger.error(
            "An error occured while signing the DMG, run with --debug for more details."
        )
        sys.exit(1)


@cli.command()
@click.pass_context
def notarize_dmg(ctx):
    logger.info("Notarizing DMG")
    cmd = [
        "xcrun",
        "altool",
        ctx.obj["config"]["altool_extra"],
        "-u {}".format(ctx.obj["config"]["apple_id"]),
        "-p {}".format(ctx.obj["config"]["password"]),
        "--notarize-app",
        "--primary-bundle-id {}.dmg".format(ctx.obj["config"]["bundle"]),
        "-f {}.dmg".format(ctx.obj["project"]),
    ]
    if ctx.obj["debug"]:
        cmd.append("--verbose")
    cmd = " ".join(cmd)

    logger.info("Running altool")
    uid = None
    proc = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
    for line in proc.stdout:
        line = str(line.strip(), "utf-8")
        logger.debug(line)
        m = re.match(uid_pattern, line)
        if m:
            uid = m.group(1)

    if proc.returncode:
        logger.error(
            "An error occured while notarizing the DMG, run with --debug for more details."
        )
        sys.exit(1)

    logger.info("The DMG was submitted. The UID is: '{}'".format(uid))

    return uid


@cli.command()
@click.pass_context
def staple_dmg(ctx):
    logger.info("Stapling DMG")
    cmd = ["xcrun", "stapler", "staple", "{}.dmg".format(ctx.obj["project"])]
    if ctx.obj["debug"]:
        cmd.append("--verbose")
    cmd = " ".join(cmd)

    logger.info("Running stapler")
    proc = Popen(cmd, shell=True, stdout=PIPE, stderr=STDOUT)
    for line in proc.stdout:
        logger.debug(str(line.strip(), "utf-8"))

    if proc.returncode:
        logger.error(
            "An error occured while stapling the notarization ticket to the DMG, run with --debug for more details."
        )
        sys.exit(1)


@cli.command()
@click.pass_context
@click.option("-uid", help="The UID to check the status for", type=str)
def status(ctx, uid):
    if not uid:
        cmd = [
            "xcrun",
            "altool",
            ctx.obj["config"]["altool_extra"],
            "-u {}".format(ctx.obj["config"]["apple_id"]),
            "-p {}".format(ctx.obj["config"]["password"]),
            "--notarization-history 0",
        ]
        cmd = " ".join(cmd)

        logger.info("Retrieving general status information")
        proc = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
        data = []
        divider_found = False
        for line in proc.stdout:
            line = str(line.strip(), "utf-8")
            if line:
                logger.debug(line)
            if not line:
                divider_found = False
            if divider_found:
                m = re.match(status_pattern, line)
                datetime = arrow.get(m.group(1), "YYYY-MM-DD HH:mm:ss Z")
                data.append((datetime, m.group(2), m.group(3)))
            if "----" in line:
                divider_found = True

        if proc.returncode:
            logger.error(
                "An error occured while fetching the status, run with --debug for more details."
            )
            sys.exit(1)

        latest_entry = sorted(data, key=lambda x: x[0], reverse=True)[0]
        latest_id = latest_entry[1]

    cmd = [
        "xcrun",
        "altool",
        ctx.obj["config"]["altool_extra"],
        "-u {}".format(ctx.obj["config"]["apple_id"]),
        "-p {}".format(ctx.obj["config"]["password"]),
        "--notarization-info {}".format(uid or latest_id),
        "--output-format json",
    ]
    cmd = " ".join(cmd)

    logger.info("Retrieving status details for {}".format(uid or latest_id))
    proc = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)

    data = ""
    for line in proc.stdout:
        line = str(line.strip(), "utf-8")
        if line:
            logger.debug(line)
        data += line

    if proc.returncode:
        logger.error(
            "An error occured while fetching the status, run with --debug for more details."
        )
        sys.exit(1)

    data = json.loads(data)

    try:
        status = data["notarization-info"]["Status"]
    except Exception:
        logger.exception("The UID either does not exist or was not submitted yet.")
        return

    if status == "success":
        logger.info("The notarization succeeded!")
    elif status == "in progress":
        logger.info("The notarization is in progress.")
    else:
        logger.error("The notarization failed.")
        logger.error(
            "The log file can be accessed here: {}".format(
                data["notarization-info"]["LogFileURL"]
            )
        )
        sys.exit(1)

    return status


@cli.command()
@click.pass_context
def full_run(ctx):
    logger.info("Full Notarization Run")
    ctx.invoke(unpack_app)
    ctx.invoke(sign_app)
    uid = ctx.invoke(notarize_app)

    while True:
        notarization_status = ctx.invoke(status, uid=uid)
        if notarization_status == "success":
            logger.info("Notarization check passed, proceeding to next step.")
            break
        elif notarization_status == "invalid":
            logger.error("Notarization check failed, stopping.")
            sys.exit(1)
        logger.info("Notarization still in progress, re-checking in 30 seconds.")
        time.sleep(30)

    ctx.invoke(staple_app)
    ctx.invoke(pack_dmg)
    ctx.invoke(sign_dmg)
    uid = ctx.invoke(notarize_dmg)

    while True:
        notarization_status = ctx.invoke(status, uid=uid)
        if notarization_status == "success":
            logger.info("Notarization check passed, proceeding to next step.")
            break
        elif notarization_status == "invalid":
            logger.error("Notarization check failed, stopping.")
            sys.exit(1)
        logger.info("Notarization still in progress, re-checking in 1 minute.")
        time.sleep(60)

    ctx.invoke(staple_dmg)

    logger.info("Cleaning up temporary artifacts")
    os.remove("entitlements.plist")
    os.remove("{}-app.zip".format(ctx.obj["project"]))
    shutil.rmtree(ctx.obj["project"])

    logger.info(
        "[green]Success![/green] The file [salmon]{}.dmg[/salmon] is now fully notarized and ready to be shipped.".format(
            ctx.obj["project"]
        )
    )


if __name__ == "__main__":
    cli()

#!/usr/bin/env python3

import ast
import datetime
import logging
import os
import pprint
import shutil
from types import CodeType

import markdown

logging.basicConfig(level=logging.INFO, format="%(message)s")


API_HOST = "https://api.bluepilot.app"
ATHENA_HOST = "wss://ws.bluepilot.app"
MAPS_HOST = "https://maps.bluepilot.app"

FILE_ATHENAD = ["selfdrive/athena/athenad.py", "system/athena/athenad.py"]
FILE_POWER_MONITORING = ["system/hardware/power_monitoring.py", "system/thermald/power_monitoring.py", "selfdrive/thermald/power_monitoring.py"]
FILE_NAVD = "selfdrive/navd/navd.py"


def get_path(path: str | list[str]) -> str:
    if isinstance(path, str):
        return path
    for p in path:
        if os.path.exists(p):
            return p
    raise ValueError(f"File not found: {path}")


def append(path: str | list[str], content: str, end_of_line="\n"):
    with open(get_path(path), "a") as f:
        f.write(content + end_of_line)


def replace(path: str, old: str, new: str):
    with open(path) as f:
        content = f.read()
    if old not in content:
        raise ValueError(f"Old value '{old}' not found in {path}")
    content = content.replace(old, new)
    with open(path, "w") as f:
        f.write(content)


def delete(path: str):
    shutil.rmtree(path)


class ASTWriter(object):
    def __init__(self, path: str):
        self.path = path

    def __enter__(self) -> CodeType:
        with open(self.path, "r") as f:
            content = f.read()
        self.tree = ast.parse(content)

        self.interpreter = None
        if content.startswith("#!"):
            self.interpreter = content[0 : content.index("\n") + 1]

        return self.tree

    def __exit__(self, *args):
        content = ast.unparse(self.tree)
        with open(self.path, "w") as f:
            if self.interpreter:
                f.write(self.interpreter)
            f.write(content + "\n")


def patch_assignment(path: str, variable_name: str, value: str):
    with ASTWriter(path) as tree:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name) or target.id != variable_name:
                    continue
                node.value = ast.parse(value).body[0].value


def patch_method_noop(path: str | list[str], method_name: str):
    """Replace method with a no-op 'return' statement"""
    with ASTWriter(get_path(path)) as tree:
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name != method_name:
                continue
            node.body = [ast.parse("return").body[0]]


def patch_method(path: str | list[str], method_name: str, code: str):
    """Replace method with custom code"""
    with ASTWriter(get_path(path)) as tree:
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef) or node.name != method_name:
                continue
            node.body = ast.parse(code).body


def strip_github_workflows() -> str:
    delete(".github/workflows")
    return "remove github workflows"


def patch_api() -> str:
    append("launch_env.sh", f'export API_HOST="{API_HOST}"')
    append("launch_env.sh", f'export ATHENA_HOST="{ATHENA_HOST}"')
    return "api: update host"


def patch_power_monitoring() -> str:
    replace(
        get_path(FILE_POWER_MONITORING),
        "MAX_TIME_OFFROAD_S = 30*3600",
        "MAX_TIME_OFFROAD_S = 3*3600",
    )
    return "hardwared: set MAX_TIME_OFFROAD_S to 3 hours"


def patch_nav():
    # NOTE: openpilot doesn't support this as an environment variable, only setting the token directly
    replace("selfdrive/navd/navd.py", "https://maps.comma.ai", MAPS_HOST)
    return "navd: use custom maps proxy"


# def patch_ford() -> str:
#     value = "FwQueryConfig(requests=[])"
#     patch_assignment("selfdrive/car/nissan/values.py", "FW_QUERY_CONFIG", value)
#     return "ford: remove conflicting nissan fw queries"


def patch_athena() -> str:
    patch_method_noop(FILE_ATHENAD, "log_handler")
    patch_method_noop(FILE_ATHENAD, "stat_handler")

    append(
        FILE_ATHENAD,
        "@dispatcher.add_method\n"
        + "def ping() -> None:\n"
        + "  last_ping = int(time.monotonic() * 1e9)\n"
        + "  Params().put('LastAthenaPingTime', str(last_ping))\n",
    )

    patch_method(
        FILE_ATHENAD,
        "ws_recv",
        "while not end_event.is_set():\n"
        + "  try:\n"
        + "    opcode, data = ws.recv_data(control_frame=True)\n"
        + "    if opcode == ABNF.OPCODE_TEXT:\n"
        + "      data = data.decode('utf-8')\n"
        + "      recv_queue.put_nowait(data)\n"
        + "  except WebSocketTimeoutException:\n"
        + "    last_ping = int(Params().get('LastAthenaPingTime') or b'0')\n"
        + "    ns_since_last_ping = int(time.monotonic() * 1e9) - last_ping\n"
        + "    if ns_since_last_ping > RECONNECT_TIMEOUT_S * 1e9:\n"
        + "      cloudlog.exception('athenad.ws_recv.timeout')\n"
        + "      end_event.set()\n"
        + "  except Exception:\n"
        + "    cloudlog.exception('athenad.ws_recv.exception')\n"
        + "    end_event.set()\n",
    )

    return (
        "athenad: tweaks and bug fixes\n"
        + "- disable log and stat handlers\n"
        + "- add ping method\n"
        + "- ws_recv: ignore binary messages\n"
        + "- ws_recv: update last ping time check\n"
    )


def list_supported_hardware() -> list[str]:
    path = "system/hardware" if os.path.isdir("system/hardware") else "selfdrive/hardware"
    return list(filter(lambda x: os.path.isdir(f"{path}/{x}") and x != "pc", os.listdir(path)))


def hardware_human_readable(hardware: str) -> str:
    if hardware == "eon":
        return "comma two"
    elif hardware == "tici":
        return '<a href="https://comma.ai/shop/comma-3x" target="_blank">comma 3/3X</a>'
    else:
        return hardware


BRANCHES = [
    # local branch, remote branch, patches
    (
        "master",
        "master",
        [strip_github_workflows, patch_api, patch_nav, patch_athena],
    ),
    (
        "nightly-3h-power-off",
        "nightly",
        [patch_api, patch_nav, patch_athena, patch_power_monitoring],
    ),
] + [
    (
        branch,
        branch,
        [patch_api, patch_nav, patch_athena]
    ) for branch in ["master-ci", "nightly", "devel-staging", "devel", "release3-staging", "release3"]
] + [
    (
        branch,
        branch,
        [patch_api, patch_athena]
    ) for branch in ["release2-staging", "release2"]
]


def prepare_op_repo():
    """
    Prepare the openpilot repo
    """
    logging.info("Setting up openpilot repo.")

    os.system("git remote add commaai https://github.com/commaai/openpilot.git")

    logging.info("Done setting up openpilot repo.")


def generate_branch(local, remote, patches) -> str:
    """
    Make a new branch from remote with patches applied
    """

    logging.info("Generating branch %s", local)

    # Make sure branch is clean
    os.system(f"git fetch commaai {remote}")
    os.system(f"git checkout -B {local} FETCH_HEAD")

    # Get date of current commit
    commit_date = os.popen("git log -1 --format=%cd --date=iso-strict").read()
    author_date = os.popen("git log -1 --format=%ad --date=iso-strict").read()
    env = f"GIT_AUTHOR_DATE='{author_date}' GIT_COMMITTER_DATE='{commit_date}'"

    # Apply patches to the branch
    messages = []
    for patch in patches:
        message = patch()
        messages.append(message)

        # Commit the patch
        os.system("git add -A")
        os.system(f"{env} git commit -m '{message}'")

    # skip custom branch
    # if local in ("incognitojam", ):
    #     return ""

    supported_hardware = ["eon"] if local == "release2" else list_supported_hardware()
    supported_hardware = list(map(hardware_human_readable, supported_hardware))

    output = f"<h3>{local}</h3>"
    output += "<ul>"
    output += f"<li>Supported hardware: {', '.join(supported_hardware)}</li>"
    output += f"<li>Custom Software URL: <code>installer.comma.ai/dash-software-ltd/{local}</code></li>"
    output += f'<li><a href="https://github.com/dash-software-ltd/openpilot/commits/{local}">View source code on GitHub</a></li>'
    output += "<li><details><summary>Change log:</summary>"
    output += "<ul>"
    for message in messages:
        message = message.split("\n")
        if len(message) == 1:
            output += "<li>" + message[0] + "</li>"
        else:
            output += "<li>" + message[0] + "<ul>"
            for line in filter(bool, message[1:]):
                output += "<li>" + line.lstrip("- ").lstrip("* ") + "</li>"
            output += "</ul></li>"
    output += "</ul></details></li>"
    output += "</ul>"
    return output


def generate():
    # Restore docs branch
    os.system("git checkout --force docs")

    # Generate a date for the page
    now = datetime.datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")

    # Generate HTML output
    header = """
<html>
<head>
<title>bluepilot fork generator</title>
<style>
body {
    font-family: sans-serif;
}
code {
    background: lightgray;
    border-radius: 4px;
    padding: 2px;
}
</style>
</head>
<body>
"""

    with open("README.md") as f:
        header += markdown.markdown(f.read())
        header += "\n"

    body = "<hr><h2>Branches</h2>\n"

    # Generate branches
    for local, remote, patches in BRANCHES:
        body += generate_branch(local, remote, patches) + "\n"

    footer = f"""<hr>
<p>
This page was generated at {now_str}.
</p>
</body>
</html>
"""
    # Make pages directory if it doesn't exist
    os.system("mkdir -p pages")
    with open("pages/index.html", "w") as f:
        f.write(header + body + footer)


def main(push=True):
    prepare_op_repo()

    branch_names = [branch[0] for branch in BRANCHES]

    logging.info("branches:")
    logging.info(pprint.pformat(branch_names))

    generate()

    if push:
        # Push branches
        logging.info("Pushing branches to origin")
        for branch in branch_names:
            # os.system(f"git fetch origin {branch}")
            os.system(f"git push --no-verify --force --set-upstream origin {branch}")


if __name__ == "__main__":
    # Check if args has dry run, if so, don't push
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--no-dry-run":
        main()
    else:
        main(push=False)

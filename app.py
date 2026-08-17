import re
from typing import Any, Dict, List
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()

REQUIRED_PERMISSIONS = {
    "contents": "read",
    "packages": "write",
    "id-token": "none",
}

COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def evaluate_release_gate(payload: Dict[str, Any]) -> List[str]:
    violations: List[str] = []

    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")
    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    # 1. Least privilege permissions
    perms = workflow.get("permissions", {})
    if perms != REQUIRED_PERMISSIONS:
        violations.append("EXCESS_PERMISSION")

    # 2. PR trigger check
    if event == "pull_request" or workflow.get("trigger") == "pull_request":
        if workflow.get("trigger") == "pull_request_target":
            violations.append("UNSAFE_PR_TRIGGER")
    elif workflow.get("trigger") == "pull_request_target":
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Test matrix and pass checks
    tests_passed = workflow.get("testsPassed") is True
    matrix_complete = workflow.get("matrixComplete") is True
    fail_fast = workflow.get("failFast") is False

    if not (tests_passed and matrix_complete and fail_fast):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action Pinning Check
    actions = workflow.get("actions", [])
    for action in actions:
        owner = action.get("owner", "")
        action_ref = action.get("ref", "")
        if owner == "actions":
            # Allowed to use version tag or commit SHA
            continue
        else:
            # Third-party action must be a 40-character lowercase hexadecimal commit SHA
            if not COMMIT_SHA_PATTERN.match(action_ref):
                violations.append("MUTABLE_ACTION")
                break

    # 5. Image Checks
    if not image.get("multiStage", False):
        violations.append("SINGLE_STAGE_IMAGE")

    if image.get("runsAsRoot", True):
        violations.append("ROOT_RUNTIME")

    secret_mode = image.get("secretMode")
    if secret_mode not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    critical_cves = image.get("criticalVulnerabilities", 0)
    if critical_cves is None or critical_cves > 0:
        violations.append("CRITICAL_CVE")

    if not image.get("digestPinned", False):
        violations.append("UNPINNED_IMAGE")

    # 6. Production specific checks
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return violations


@app.post("/release-gate")
async def release_gate(request: Request):
    try:
        data = await request.json()
    except Exception:
        data = {}

    violations = evaluate_release_gate(data)
    decision = "promote" if len(violations) == 0 else "block"

    return JSONResponse(
        status_code=200,
        content={"decision": decision, "violations": violations},
    )
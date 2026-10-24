# Worksheet 13 — Cloud & Container Security (4 hrs)

> **Course:** Software Security (KOSEN69) · Week 13
> **Aligned to:** OWASP 2025 **A02 Security Misconfiguration** · **CWE-732** (incorrect permission assignment), **CWE-16** (configuration), plus CWE-798, CWE-250, CWE-538, CWE-269, CWE-1104
> **Signature game:** 🔍 *Misconfig Hunt* (CloudGoat-style) — each misconfig you find **and** fix = a flag.

> ⚠️ **Ethics note:** All artifacts here are deliberately broken for teaching and are marked *"Sandbox/teaching only; for authorized lab use."* Scan, exploit, and harden **only** these lab files (or systems you own / are authorized to test). Never point Trivy or these techniques at third-party cloud accounts or images without written permission.

---

## Part 1 — Student Information

| Name | Student ID | Date | Group | AI Use |
|------|-----------|------|-------|
| Kay Khine Maw | 6631503060 | 24 Oct 2026 | - | Used ChatGpt for drafting answers and guidance; commands and findings were verified locally. |

---

## Part 2 — Lecture Questions

Answer in your own words (2–4 sentences each).

1. Explain the **shared-responsibility model**. In `harden.md` it says "the cloud provider secures *of* the cloud; you secure what you put *in* it." Give one concrete example of each side for an S3-backed app.

   The cloud provider secures the underlying cloud infrastructure, such as the physical servers, storage hardware, and managed S3 service itself. The application owner secures what they configure and store in S3, such as making the bucket private and granting the app only the required object access.

2. `iam-policy-insecure.json` uses `"Action": "*"` and `"Resource": "*"`. Describe **why this violates least privilege** and map it to CWE-732 vs CWE-269 — what is the difference between the two CWEs here?

   `"Action": "*"` permits every operation and `"Resource": "*"` applies it to every resource, so a leaked identity could read, modify, or delete far more than this app needs. The overly broad assigned permission is CWE-732 (incorrect permission assignment), while CWE-269 (improper privilege management) describes the broader failure to manage privileges according to roles and least privilege; this policy demonstrates both.

3. The insecure Dockerfile bakes `ENV API_TOKEN=sk_live_...`. Explain how an attacker recovers that secret from a shipped image (name the `docker` commands) and why this is **CWE-798 / CWE-200**.

   After obtaining the image, an attacker can run `docker history --no-trunc IMAGE` to inspect the layer-created environment setting and `docker inspect IMAGE` to read `Config.Env`; running a container and examining its environment can expose it as well. This is CWE-798 because the credential is hard-coded into the image, and CWE-200 because shipping the image exposes that sensitive information to anyone who can access it.

4. Why is `FROM python:latest` (CWE-1104/CWE-16) a security and reproducibility problem, and how does pinning to an `@sha256:` digest fix it?

   The `latest` tag is mutable, so separate builds can silently use different Python versions, operating-system packages, and vulnerabilities, making the result difficult to reproduce and audit. Pinning the `FROM` reference to an `@sha256:` digest selects an immutable image manifest, so every build uses the same verified bytes until the digest is intentionally updated and rescanned.

5. What does a **distroless** base image remove (relative to `python:3.11-slim`), and how does that shrink the attack surface for an RCE or container-escape attacker?

   A distroless image removes the general-purpose userland found in `python:3.11-slim`, including a shell, package manager, and many command-line utilities and unused libraries; it contains only the runtime and application dependencies needed to start the service. That leaves an attacker fewer tools and fewer vulnerable components to use after an RCE, reducing post-exploitation options and the chance of a container breakout, although it does not replace non-root execution and other isolation controls.

---

## Part 3 — Hands-on Lab (180 min)

**Learning goals:** find cloud/container misconfigurations with Trivy, map each to a CWE, and rebuild the IAM policy + Dockerfile to least privilege / hardened so the findings drop.

**Prerequisites:** Docker installed and running; the `week13-cloud-container/` lab folder; internet access to pull `aquasec/trivy:latest`.

### Environment setup (real commands)

```bash
cd labs/week13-cloud-container

# Option A — the provided wrapper (trivy config over the Dockerfiles; IAM JSON is reviewed manually, see Task 2):
bash scan.sh

# Option B — run Trivy directly (MEDIUM is in the filter on purpose: one of the
# three rules Task 1 asks you to cite is rated MEDIUM, and HIGH,CRITICAL hides it):
docker run --rm -v "$PWD:/src" aquasec/trivy:latest config --severity MEDIUM,HIGH,CRITICAL /src

# (Optional) build + CVE-scan the hardened image:
docker build -f Dockerfile.hardened -t week13-hardened:lab .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image --severity HIGH,CRITICAL week13-hardened:lab
```

**What to submit per task:** the command(s) you ran + the relevant output (finding count or the specific finding line), a screenshot of the Trivy/terminal result, and a 2–3 sentence mitigation explaining *why* the fix reduces risk (cite the CWE).

![The same app shipped as two stacked container images, Dockerfile.insecure beside Dockerfile.hardened, with each layer paired to its fix and its CWE, and only the unpinned :latest tag, the root user and the ENV secret marked as things trivy config actually flags.](img/container-hardening.svg)

### Tasks

- **Task 0 — Onboarding (15 min).** Confirm Docker works (`docker version`), run `bash scan.sh`, and record the **baseline finding count** against `Dockerfile.insecure` (Trivy's `config` scanner does not parse standalone IAM policy JSON, so `iam-policy-insecure.json` is reviewed manually instead — see Task 2). **Deliverable:** screenshot of the baseline scan.

**Confirm Docker works (`docker version`)**

![alt text](image.png)

**Trivy summary and findings**

![alt text](image-1.png)
![alt text](image-2.png)

---

- **Task 1 — Misconfig Hunt: container image (40 min).** *Goal:* find every defect in `Dockerfile.insecure`. *Steps:* read each `# DEFECT:` comment, then locate the matching Trivy finding where one exists — only 3 of the 6 (unpinned `:latest`, runs as root, secrets in `ENV`) map to a Trivy config rule (`DS-0001`, `DS-0002`, `DS-0031`); `COPY . .`, `chmod -R 777`, and unpinned `pip install` are instruction-level RUN/COPY semantics Trivy's Dockerfile scanner doesn't check, so identify those 3 by code review instead. Build a table: defect → CWE → Trivy rule/severity (write "manual review — no Trivy rule" where none exists). *Deliverable:* completed table (6 rows) using the IDs from `harden.md`.

**Completed defect table**

1. **Defect:** `FROM python:latest` is unpinned and mutable (**harden.md #1**).  
   **CWE:** CWE-1104 / CWE-16  
   **Trivy rule/severity:** DS-0001 / MEDIUM  
   **Why it is dangerous:** The `latest` tag can point to different image contents over time, so builds are not reproducible and may silently receive an unreviewed or vulnerable base image.

2. **Defect:** Hard-coded credentials in `ENV API_TOKEN=...` and `ENV AWS_SECRET_ACCESS_KEY=...` (**harden.md #2**).  
   **CWE:** CWE-798 / CWE-200  
   **Trivy rule/severity:** DS-0031 / CRITICAL  
   **Why it is dangerous:** Secrets are stored in image metadata and layers, where anyone who can access the shipped image may recover and misuse them.

3. **Defect:** `COPY . .` copies the entire build context (**harden.md #3**).  
   **CWE:** CWE-538  
   **Trivy rule/severity:** Manual review — no Trivy Dockerfile rule  
   **Why it is dangerous:** The image may include `.git`, `.env`, private keys, and other files that were not intended for distribution.

4. **Defect:** `chmod -R 777 /app` assigns world-writable permissions (**harden.md #4**).  
   **CWE:** CWE-732  
   **Trivy rule/severity:** Manual review — no Trivy Dockerfile rule  
   **Why it is dangerous:** Any process in the container can modify the application files, enabling tampering or persistence after a compromise.

5. **Defect:** No `USER` instruction, so the container runs as root (**harden.md #5**).  
   **CWE:** CWE-250  
   **Trivy rule/severity:** DS-0002 / HIGH  
   **Why it is dangerous:** An RCE starts with unnecessary root privileges, increasing the impact of a container compromise or attempted escape.

6. **Defect:** `pip install -r requirements.txt` uses unpinned dependencies (**harden.md #6**).  
   **CWE:** CWE-1104  
   **Trivy rule/severity:** Manual review — no Trivy Dockerfile rule  
   **Why it is dangerous:** Future builds can resolve different dependency versions, including a compromised or vulnerable release, without an intentional code change.

---

- **Task 2 — Misconfig Hunt: IAM (30 min).** *Goal:* document why `iam-policy-insecure.json` is full-admin. *Steps:* identify the `Action:*` / `Resource:*` / no-`Condition` problems; map to CWE-269 / CWE-732. *Deliverable:* 3-row table + one sentence on the blast radius if these creds leak.

**IAM misconfiguration table**

| # | Defect in `iam-policy-insecure.json` | CWE | Why it violates least privilege | Hardened fix |
|---|---|---|---|---|
| 1 | `"Action": "*"` permits every AWS API action. | CWE-269 — improper privilege management | The application receives administrative capabilities instead of only the S3 operations it needs. | Enumerate only required actions, such as `s3:GetObject` and, where needed, `s3:ListBucket`. |
| 2 | `"Resource": "*"` applies the permission to every AWS resource. | CWE-732 — incorrect permission assignment | The permission is not limited to the application’s bucket or object prefix, so unrelated resources are in scope. | Restrict access to specific ARNs, including `arn:aws:s3:::lab-app-bucket/app/*` for objects. |
| 3 | No `Condition` further restricts when or where the permission can be used. | CWE-732 — incorrect permission assignment | Even the intended list operation has no prefix constraint, allowing access beyond the application’s required `app/` path. | Add a condition such as `StringLike` → `s3:prefix` → `app/*` for `s3:ListBucket`. |

**Blast radius:** If these credentials leak, an attacker could perform any allowed AWS action against any allowed resource, potentially reading, modifying, or deleting unrelated data and infrastructure across the account.

---

- **Task 3 — Secrets & storage (25 min).** *Goal:* show secrets must not live in the image. *Steps:* explain how `ENV API_TOKEN` / `AWS_SECRET_ACCESS_KEY` are exposed via `docker history`; propose where they belong instead (secrets manager / mounted secret / orchestrator secret per `harden.md`). *Deliverable:* 2–3 sentence remediation + the `.dockerignore` entries you would add to stop `COPY . .` leaking `.git`/`.env` (CWE-538).

![alt text](image-3.png)
![alt text](<Screenshot 2026-10-24 100858.png>)
![alt text](<Screenshot 2026-10-24 101254.png>)

**Secrets and storage remediation**

Never place `API_TOKEN`, `AWS_SECRET_ACCESS_KEY`, or other credentials in Dockerfile `ENV` instructions, source control, or image layers; inject them at runtime from a secrets manager, mounted secret, or orchestrator secret, and rotate any credential that has already been exposed. Use a `.dockerignore` file to prevent the build context from copying sensitive repository files into the image, which mitigates CWE-538 but does not replace proper runtime secret management.

```text
.git
.gitignore
.env
.env.*
*.pem
*.key
*.secret
secrets/
```
---

- **Task 4 — Hardened-Dockerfile + least-priv-IAM defense (50 min).** *Goal:* prove the "after" is clean. *Steps:* (a) re-run `bash scan.sh` (or `trivy config`) against `Dockerfile.hardened` and capture the **reduced** finding count (Trivy's config scanner does not parse standalone IAM JSON, so confirm the IAM fix manually per Task 2 by diffing `iam-policy-leastpriv.json` against the insecure policy); (b) for the Dockerfile, point to the fix for each Task-1 defect (digest pin, multi-stage venv, distroless runtime, `USER 65532:65532`, no secrets in `ENV`, copy only `app.py`); (c) for IAM, confirm the rewrite scopes `s3:GetObject` to `arn:aws:s3:::lab-app-bucket/app/*` and adds the `s3:prefix` `Condition`; (d) list the extra runtime flags from `harden.md` (`--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`). *Deliverable:* before/after finding counts, the defect→fix mapping, and the diffed policy/Dockerfile with one sentence per fix.

![alt text](image-6.png)
![alt text](image-7.png)
![alt text](image-8.png)
![alt text](<Screenshot 2026-10-24 104125.png>)
![alt text](image-9.png)

**Before/after finding counts:** Using `trivy config --severity MEDIUM,HIGH,CRITICAL /src`, `Dockerfile.insecure` produced **4 findings**: one DS-0001/MEDIUM, one DS-0002/HIGH, and two DS-0031/CRITICAL findings. `Dockerfile.hardened` produced **0 findings** under the same severity filter, so the hardened Dockerfile reduced the Trivy count from 4 to 0.

**Dockerfile defect → fix mapping:**

| Insecure defect | Hardened fix | Why the fix reduces risk |
|---|---|---|
| `FROM python:latest` (CWE-1104/CWE-16) | Use the digest-pinned `python:3.11-slim@sha256:...` build image and digest-pinned distroless runtime image. | Immutable digests make the base contents reproducible and prevent a mutable tag from silently changing the build. |
| Secrets in `ENV` (CWE-798/CWE-200) | Remove `API_TOKEN` and `AWS_SECRET_ACCESS_KEY` from the Dockerfile and inject secrets at runtime. | Secrets are no longer stored in image metadata or layers that can be recovered from a shipped image. |
| `COPY . .` (CWE-538) | Copy only `requirements.txt` and `app.py`, with sensitive files excluded by `.dockerignore`. | Limiting the build context contents prevents repository files, environment files, and keys from entering the image. |
| `chmod -R 777 /app` (CWE-732) | Do not make the application directory world-writable; use the default restrictive permissions. | Processes that do not own the application can no longer freely tamper with its code and files. |
| No `USER` instruction (CWE-250) | Run as `USER 65532:65532` in the distroless runtime. | A compromised process starts without root privileges, reducing the impact of RCE and attempted container escape. |
| Unpinned `pip install` (CWE-1104) | Install the pinned dependencies in the disposable build stage and copy the resulting virtual environment into runtime. | Dependency resolution is more controlled, and build tooling is not shipped in the production image. |

**IAM policy diff:** The insecure policy grants `"Action": "*"` on `"Resource": "*"`, while `iam-policy-leastpriv.json` grants only `s3:GetObject` on `arn:aws:s3:::lab-app-bucket/app/*` and grants `s3:ListBucket` only on the bucket with a `StringLike` condition restricting `s3:prefix` to `app/*`. This changes the policy from full administrative scope to the minimum S3 access required by the application, addressing CWE-269 and CWE-732.

**Runtime hardening flags:** Deploy the hardened image with `--read-only`, `--cap-drop ALL`, and `--security-opt no-new-privileges`; these respectively prevent ordinary filesystem writes, remove unnecessary Linux capabilities, and block privilege escalation.

---

- **Task 5 — Flag tally (20 min).** *Goal:* score the hunt. *Steps:* one flag per misconfig found **and** fixed (6 container + 3 IAM = 9). *Deliverable:* flag count + the single biggest-risk misconfig and why.

![alt text](image-10.png)

| Category | Misconfigurations | Flags |
|---|---:|---:|
| Container image | 6 | 6 |
| IAM policy | 3 | 3 |
| **Total** | **9** | **9** |

The biggest-risk misconfiguration is the IAM policy that grants `"Action": "*"` on `"Resource": "*"`. If these credentials leak, an attacker could read, modify, or delete unrelated AWS data and infrastructure because the policy grants broad administrative access instead of limiting actions and resources to the application’s needs.

---

## Part 4 — Reflection

1. **Mapping.** For three findings, write the line of the artifact → CWE → OWASP 2025 A02, and the one-line fix.

   | Artifact finding | CWE → OWASP 2025 A02 | One-line fix |
   |---|---|---|
   | `Dockerfile.insecure`: `ENV API_TOKEN=...` | CWE-798/CWE-200 → A02 Security Misconfiguration | Remove credentials from image layers and inject them at runtime through a secrets manager or mounted secret. |
   | `iam-policy-insecure.json`: `"Action": "*"` and `"Resource": "*"` | CWE-269/CWE-732 → A02 Security Misconfiguration | Allow only the required S3 actions and scope them to the application bucket and prefix. |
   | `Dockerfile.insecure`: no `USER` instruction, so the process runs as root | CWE-250 → A02 Security Misconfiguration | Add `USER 65532:65532` and run the application as a non-root user. |

2. **Real incident.** Briefly describe a real breach caused by a cloud/container misconfiguration (e.g., a public S3 bucket leak, or an over-permissive IAM role). What single control from this lab would have prevented it?

    In 2017, Verizon suffered a data exposure after an AWS S3 storage configuration allowed sensitive customer information to be accessed publicly. The single control from this lab that would have prevented this class of incident is least-privilege storage access: keep the bucket private and restrict the application policy to the exact S3 actions, bucket, and object prefix it needs, with no public access.

3. **Best mitigation.** Of everything you did, which control gives the most risk reduction per unit of effort, and why? Argue for least-privilege IAM vs. distroless+non-root.

    Least-privilege IAM gives the greatest risk reduction per unit of effort because it limits the blast radius before a stolen credential or compromised application can reach unrelated cloud resources. Distroless and non-root execution are important defense-in-depth controls that reduce post-RCE tools and privileges, but they do not prevent an over-permissive identity from accessing cloud data; therefore I would implement least privilege first, then add distroless and non-root hardening.

---

## Grading rubric (100)

| Component | Points | What earns full marks |
|-----------|:------:|-----------------------|
| Part 2 — Lecture questions | 20 | All 5 answered correctly with CWE/A02 reasoning |
| Part 3 — Tasks + evidence | 40 | Tasks 0–5 complete; commands, outputs, and screenshots present |
| Defense (Task 4 hardening) | 25 | Hardened Dockerfile + least-priv IAM shown to reduce findings; per-fix justification |
| Part 4 — Reflection | 15 | Accurate mapping, relevant incident, well-argued best mitigation |

---

## Evidence & Integrity (required)

- **Identity proof:** every screenshot/diagram must show a terminal running `printf '%s | %s | ' "$(whoami)" '<YOUR-STUDENT-ID>'; date '+%F %T %Z'` **in the
  same image as the evidence**. When the evidence is a browser page, a DevTools panel or a
  rendered response, put that terminal **beside the browser and capture the whole screen** — a
  cropped window carries nothing that identifies you, and the lab's own output is
  byte-identical for the whole cohort *by design*, so the stamp is the only thing that makes
  the shot yours. Generic or borrowed evidence is not accepted.
- **Personalized flag (if this lab issues one):** ____________________
  *Flags are unique per student — submitting another student's flag is a violation. How to submit: **learn.zcr.ai/submit** (full guide: `SUBMISSION.md` in the repo root).*
- **Explain in your own words** *(graded on your reasoning, not copied text):*
  1. What did you do, and **why did the vulnerability work**?

      I scanned the insecure and hardened Dockerfiles with Trivy, reviewed the Dockerfile defect comments, compared the insecure and least-privilege IAM policies, and inspected how image environment variables can be recovered with Docker commands. The vulnerabilities worked because the insecure image used a mutable base tag, stored credentials in image metadata and layers, copied the whole build context, made the application world-writable, ran as root, and installed unpinned dependencies; the IAM policy also granted every action on every resource, so any exposed identity had an unnecessarily large blast radius.

  2. **Why does your fix actually stop it** — and what could still break it?

      The fix stops these paths by pinning image contents, removing secrets from image layers, copying only required files, using restrictive permissions and a non-root distroless runtime, controlling dependency versions, and limiting IAM actions and resources with an S3 prefix condition. These controls could still be undermined by a leaked runtime secret, a newly vulnerable dependency or base image that is not deliberately rescanned and updated, an overly broad policy added later, a misconfigured bucket, or unsafe deployment options such as `--privileged` or a mounted Docker socket.

---

## 🤖 Audit the AI (required)

AI is a power tool you must **distrust** — you are graded on your *critique*, not the AI's answer.

1. Ask an AI assistant to exploit **or** fix this week's vulnerability. Paste its full answer.

**AI assistant response (submitted for review):**

   > Replace `FROM python:latest` with `FROM python:3.11-slim`, remove the secret `ENV` lines, add `USER 1000`, and run `pip install -r requirements.txt`. This fixes the Dockerfile because the image is now secure and reproducible; rebuild it with `docker build -t week13-hardened:lab .` and run Trivy to confirm that there are no findings.

2. **Find what's wrong or risky** in it — insecure code, a subtly incomplete fix, a hallucinated API/function/CVE, a missed edge case, or wrong reasoning. Quote the exact line(s).

**Problems with the AI response:**

   The statement “`FROM python:3.11-slim` ... is now secure and reproducible” is incomplete because a version tag is mutable; it should be pinned to a verified `@sha256:` digest. The advice also omits the whole-context `COPY . .`, world-writable `chmod -R 777 /app`, unpinned dependency versions, the distroless runtime, and the IAM policy, and it incorrectly promises “no findings” without specifying the scanner, severity filter, or verifying the result.

3. Produce the **correct, verified** version yourself and explain in 2–3 sentences why the AI's output was insufficient.

**Corrected and verified version:**

   Use a multi-stage Dockerfile with a digest-pinned `python:3.11-slim` build image and a digest-pinned distroless runtime image; copy only `requirements.txt` and `app.py`, install pinned dependencies in the build stage, remove all secret `ENV` values, keep restrictive file permissions, and run the service as `USER 65532:65532`. Separately replace the IAM wildcards with only the required S3 actions, scope object access to `arn:aws:s3:::lab-app-bucket/app/*`, and add the `s3:prefix` condition for listing; verify with `trivy config --severity MEDIUM,HIGH,CRITICAL /src` and confirm that `Dockerfile.hardened` reports 0 findings while the insecure file reports 4 under the same filter.

      **Verification commands:**

      ```powershell
      docker build -f .\Dockerfile.hardened -t week13-hardened:lab .
      docker run --rm -v "${PWD}:/src" aquasec/trivy:latest config --severity MEDIUM,HIGH,CRITICAL /src
      git diff --no-index -- .\iam-policy-insecure.json .\iam-policy-leastpriv.json
      ```

> Disclose your AI use in the Part 1 table. This task counts toward your **Defense + Reflection** score.

---

## 🧠 Comprehension & Prompt (required)

**A. Explain in Plain English (EiPE).** In 2–3 sentences, in your own words, describe what this week's vulnerable code/endpoint actually *does* and *why it is exploitable* — explain the mechanism, don't dump jargon.

The vulnerable Dockerfile builds an image that includes the application, copies the entire build context, stores API and AWS credentials in image environment layers, installs unpinned packages, makes the application directory writable by everyone, and runs the service as root. Anyone who obtains the shipped image can inspect its history or configuration to recover the credentials, and a process-level compromise has root privileges and broad permission to alter files; the IAM policy makes the cloud impact worse by allowing every action on every resource.

**B. Prompt Problem.** Write a **single prompt** that makes an AI produce a *correct, secure* fix for one finding. Run it: does the exploit now fail? If not, refine the prompt and try again. Submit the **final prompt + the verified result**.
*Graded on the prompt's precision and your verification — this trains problem decomposition and AI literacy (Denny et al. 2024).*

**Final prompt:**

> In the authorized Week 13 teaching repository, fix only the hard-coded-secret finding in `Dockerfile.insecure`. Produce a minimal Dockerfile patch that removes `ENV API_TOKEN=...` and `ENV AWS_SECRET_ACCESS_KEY=...`, does not replace them with build arguments or other image-layer values, and explains how to inject them at runtime through a secrets manager, mounted secret, or orchestrator secret. Preserve the intentionally vulnerable lab file as a teaching artifact by showing the corrected pattern in a separate hardened Dockerfile, and provide exact local verification commands using `docker history --no-trunc` and `docker inspect`; do not print any real secret values.

**Verified result:** The corrected pattern removes both secret `ENV` instructions and supplies credentials only at runtime. After rebuilding the corrected image, `docker history --no-trunc IMAGE` no longer shows the credentials and `docker inspect IMAGE` shows no baked-in `API_TOKEN` or `AWS_SECRET_ACCESS_KEY`; the original insecure image remains intentionally vulnerable for comparison. This verifies that the image-layer exposure fails, although a runtime secret could still leak if the application logs it, exposes it through an endpoint, or the host/orchestrator is compromised.

---

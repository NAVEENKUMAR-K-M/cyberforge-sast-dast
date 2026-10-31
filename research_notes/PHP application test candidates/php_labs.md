# Established vulnerable PHP labs

## Which applications should we prioritise?

### Takeaway
Use DVWA as the first development baseline and OWASP Mutillidae II as the mandatory cross-file integration challenge. Reserve a third application from the broader research for held-out evaluation; XVWA and bWAPP are useful legacy supplements, but their setup/maintenance uncertainty makes them weaker defaults.

### Cited Findings
- **DVWA**: canonical source is [digininja/DVWA](https://github.com/digininja/DVWA), identified as PHP/MariaDB with GPL-3.0 licensing. The project includes source, vulnerability modules, tests, Dockerfile and Compose. It is a community training application; do not label it an official OWASP project merely because it teaches OWASP vulnerability classes. [Repository](https://github.com/digininja/DVWA).
- DVWA's documented Docker workflow requires Docker and Compose, supports serving local source into the container, and says development/testing targets current stable PHP. PHP 5 is unsupported and versions below 7.3 have known problems. [Installation and PHP guidance](https://github.com/digininja/DVWA/blob/master/README.md).
- DVWA's current Dockerfile uses `php:8-apache`, installs mysqli/PDO support and Composer dependencies for its API. The Compose file pairs it with MariaDB and binds the application to loopback port 4280. Its default application image is moving `latest` with `pull_policy: always`, so runtime source can diverge from a separately checked-out source tree unless pinned. [Dockerfile](https://raw.githubusercontent.com/digininja/DVWA/master/Dockerfile), [Compose](https://raw.githubusercontent.com/digininja/DVWA/master/compose.yml).
- **OWASP Mutillidae II** is verified as an actual OWASP lab project, not just a site mentioning OWASP. The foundation links the project source and Docker repositories. [OWASP project](https://owasp.org/projects/mutillidae-ii).
- Mutillidae's canonical repository is [webpwnized/mutillidae](https://github.com/webpwnized/mutillidae), GPL-3.0. Its README documents more than 40 vulnerabilities/challenges, secure/insecure modes, restoration via Setup, classes and reusable includes, and REST/SOAP components. Source is now under `src/`; older setup articles may use obsolete paths. [README](https://github.com/webpwnized/mutillidae/blob/main/README.md), [repository/license](https://github.com/webpwnized/mutillidae).
- Mutillidae has two maintainer-owned deployment options: [prebuilt DockerHub images](https://github.com/webpwnized/mutillidae-dockerhub) and [local Docker build](https://github.com/webpwnized/mutillidae-docker). Five services cover PHP/Apache, database, LDAP and management UIs. Domain expectation is `mutillidae.localhost`. The actual current prebuilt Compose binds HTTP 80, HTTPS 443, database-admin 81, LDAP-admin 82 and LDAP 389 to loopback; prefer this file over older README port lists. [Current Compose](https://raw.githubusercontent.com/webpwnized/mutillidae-dockerhub/main/docker-compose.yml).
- Mutillidae's build Dockerfile starts from moving `php:apache`, installs PHP extensions, clones the application source from its current branch and copies `src` into its served location. This is a maintenance signal and a reproducibility concern: record the actual deployed source revision rather than assuming a Docker tag equals a local checkout. [Dockerfile](https://raw.githubusercontent.com/webpwnized/mutillidae-docker/main/.build/www/Dockerfile).
- **XVWA** canonical source is [s4n7h0/xvwa](https://github.com/s4n7h0/xvwa), PHP/MySQL, GPL-3.0. It is explicitly archived/read-only since 18 November 2025. It is a community project, not verified as an official OWASP project. [Repository](https://github.com/s4n7h0/xvwa).
- XVWA documents error/blind SQLi, OS command injection, reflected/stored/DOM XSS, file inclusion and unvalidated redirects among other categories. It gives Apache/PHP/MySQL installation, setup/reset UI and test accounts. Its Docker recommendation points to a third-party project rather than an in-repository maintained Compose. No exact current PHP compatibility guarantee was verified. [XVWA README](https://github.com/s4n7h0/xvwa/blob/master/README.md).
- **bWAPP** has an identifiable author-owned [SourceForge project](https://sourceforge.net/projects/bwapp/), by Malik Mesellem/mmesellem, with PHP/MySQL source and local AMP/bee-box installation. It lists 100+ bugs including SQLi, XSS, command injection, traversal, LFI/RFI and redirects; form-auth and no-auth modes are documented. Page last-update metadata is 21 May 2018. It is ITSEC GAMES, not verified as official OWASP. [Project page](https://sourceforge.net/projects/bwapp/).
- bWAPP's source browser is especially stale: the visible master tree is version 1.9+ from April 2014, while downloadable releases may differ. Do not conflate the source-browser revision with an arbitrary Docker image/version. [Official code tree](https://sourceforge.net/p/bwapp/code/ci/master/tree/).

### Inferences
- DVWA is the lowest-friction first target on evidence reviewed: first-party Compose, modern PHP base and clear vulnerable/protected variants.
- Mutillidae should be a deliberate integration gate, not postponed until the end: it exercises front-controller routes, parameter-selected includes, shared application state and object-method flows.
- XVWA is a reasonable lighter second procedural codebase if its environment is made reproducible. bWAPP supplies broader legacy coverage but could consume hackathon time on runtime compatibility rather than engine correctness.
- First-party Compose existing is evidence of a supported setup path, not proof that we have successfully run it on the user's machine. No target was installed or scanned in this research.

### Gaps
- Exact PHP 8 compatibility for bWAPP/XVWA was not established. bWAPP license text was not retrievable from an authoritative source during this review: call it author-described free/open-source, do not invent an SPDX license or borrow a Docker wrapper's license.
- No full endpoint/line/CWE ground-truth manifest was verified for these labs. Challenge counts are not equivalent to correlation-pair counts.
- Exact latest commit dates for DVWA and Mutillidae were not reliably exposed; avoid unsupported claims such as “actively maintained as of this month.” Stronger verified signals are current first-party setup instructions and actual PHP image definitions.

## What actual source patterns make these useful for correlation?

### Takeaway
DVWA already contains a particularly strong cross-file shared-variable case; Mutillidae adds cross-method/object state. These are substantially more valuable than verifying that the scanner notices SQL strings in isolated files.

### Cited Findings
- **DVWA SQLi:** public `vulnerabilities/sqli/index.php` requires authentication, selects low/medium/high/impossible implementation via security-level state, then includes `source/{$vulnerabilityFile}`. Medium changes the form method to POST. The caller later renders `$html`, which implementations populate. [Entry-point source](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/sqli/index.php).
- The low implementation reads request `id`, interpolates it into a query and executes mysqli or SQLite depending on application configuration; it appends output into shared `$html`. [Low SQLi source](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/sqli/source/low.php).
- The corresponding impossible SQLi implementation validates numeric input and uses prepared statements with bound parameters; it also checks a CSRF token. This gives a specific protected comparison case, rather than assuming every high security level is safe. [Protected SQLi source](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/sqli/source/impossible.php).
- **DVWA cross-file file inclusion:** `fi/source/low.php` assigns `$_GET['page']` to `$file`; the parent `fi/index.php`, after selecting and requiring that implementation, performs `include($file)`. Thus the input source and dangerous include operation are genuinely in different files with shared include scope. [Input assignment](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/fi/source/low.php), [parent include operation](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/fi/index.php).
- DVWA low reflected XSS appends request `name` to `$html`; command injection reads request `ip` and concatenates it into `shell_exec` ping commands; open redirect passes request `redirect` into the Location header. These cover additional relevant operations, but runtime evidence still needs independent checking. [Reflected XSS](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/xss_r/source/low.php), [command injection](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/exec/source/low.php), [redirect](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/open_redirect/source/low.php).
- **Mutillidae dispatch:** `src/index.php` loads shared handler classes, sets up session/security state, obtains the `page` request value, and eventually requires the selected file. Its authenticated-page list includes user-info, dns-lookup and text-file-viewer; missing login redirects to the login page. [Front-controller source](https://raw.githubusercontent.com/webpwnized/mutillidae/main/src/index.php).
- Mutillidae `user-info.php` reads request username/password (or POST in protected mode) and calls `$SQLQueryHandler->getUserAccount`. It uses a route of `index.php?page=user-info.php`, not merely a unique pathname. [Input/call/form source](https://raw.githubusercontent.com/webpwnized/mutillidae/main/src/user-info.php).
- In another file, `SQLQueryHandler::getUserAccount` constructs the account query and forwards it to `MySQLHandler::executeQuery`; protection depends on the object's security-level-derived state. [SQL helper source](https://raw.githubusercontent.com/webpwnized/mutillidae/main/src/classes/SQLQueryHandler.php).
- **XVWA:** SQLi `index.php` includes `home.php`; `home.php` includes the database config and handles POST `item` or `search` in distinct branches, with different SQL constructions. This provides another include-driven entry-point mapping and input-branch attribution case. [Entry](https://raw.githubusercontent.com/s4n7h0/xvwa/master/vulnerabilities/sqli/index.php), [included logic](https://raw.githubusercontent.com/s4n7h0/xvwa/master/vulnerabilities/sqli/home.php).

### Inferences
- Our baseline should explicitly verify DVWA flow from included low.php back into the parent's include sink. A scanner that only scans files independently may miss it even if it identifies other local SQLi bugs.
- Same URL/CWE is inadequate. DVWA requires distinguishing which security-level implementation executed. Mutillidae requires keeping dispatch parameter `page` in route identity rather than stripping all query parameters.
- Finding both input and sink within a possible include graph proves neither feasible taint propagation nor runtime branch selection. Preserve scope, ordering, input identity and configuration; unresolved alternatives remain ambiguous.
- Source-derived include resolution is legitimate; hardcoding known DVWA filenames into endpoint-to-bug mappings would invalidate generalisation. App-specific credentials, base path, database choice and security-level configuration are legitimate test setup.
- Do not automatically classify every file inclusion test as CWE-22. File inclusion and traversal overlap in some paths but their CWE must reflect the actual root cause/evidence. Assess traversal separately.

### Gaps
- Above are inspected source patterns, not executed exploit confirmations. Exact line numbers must be refreshed against a pinned revision.
- DOM XSS is browser-side; supporting it is not automatic merely because the app backend is PHP. Stored XSS needs multi-request state and database-mediated flow; keep it separate from reflected XSS success claims.

## How should we build a defensible local benchmark?

### Takeaway
Use pinned app revisions and a curated, independently verified case manifest. Vulnerability menus and hints help build ground truth, but are not a substitute for observed runtime evidence linked to source.

### Cited Findings
- Both DVWA and Mutillidae execute alternative code according to runtime security state. Their inspected sources demonstrate this explicitly. [DVWA selection](https://raw.githubusercontent.com/digininja/DVWA/master/vulnerabilities/sqli/index.php), [Mutillidae security state](https://raw.githubusercontent.com/webpwnized/mutillidae/main/src/classes/SQLQueryHandler.php).
- Mutillidae's official Docker build fetches moving source and changes configuration at image-build time; DVWA's Compose pulls latest unless modified. [Mutillidae build](https://raw.githubusercontent.com/webpwnized/mutillidae-docker/main/.build/www/Dockerfile), [DVWA Compose](https://raw.githubusercontent.com/digininja/DVWA/master/compose.yml).
- OWASP's vulnerable-app directory also lists Bricks as a PHP/MySQL security learning platform with login/upload/content challenges; suitable as an additional small legacy lab, but source/deployment/license were not independently verified here. [OWASP directory entry](https://vwad.owasp.org/app/bricks/).

### Inferences
- Recommended sequence: DVWA low to establish baseline pairs; DVWA protected SQLi as a negative control; Mutillidae insecure user-lookup for multi-file/method correlation; XVWA as an additional procedural app if setup passes; a separately reserved broader-research app for blind evaluation.
- Record app commit, runtime source hash/image digest, PHP/database versions, security level, authentication account/role and reset state. Verify SAST sees exactly the source running behind DAST.
- For each curated case record endpoint/method/input, security configuration, root-cause file/line, CWE, expected classification, reproducible runtime observation and protected comparison where available. Keep benchmark answers outside scanner logic.
- Track SAST detection, runtime detection, correct root-cause links, wrong links and safe-case false positives separately. Do not divide by total menu entries or treat unassessed code as safe.
- Keep credentials/session config in adapters if needed, not endpoint-to-answer tables. Hold out an entire codebase from detector tuning, then disclose evaluated case coverage rather than claiming the PRD's unavailable 36-bug answer key.
- Choose local-only app deployments for the requested engine evaluation. This research inspected public repositories/documentation and did not scan any hosted demonstration.

### Gaps
- Need actual deployment smoke tests, curated manifests and independent manual validation before numerical precision/recall claims.
- Need an additional framework-based PHP app to test generalisation beyond direct-script/front-controller procedural labs; another researcher is covering that search.

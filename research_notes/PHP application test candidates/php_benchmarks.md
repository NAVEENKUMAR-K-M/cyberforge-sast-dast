# PHP benchmarks and alternative applications

## Which complete PHP applications add useful test diversity?

### Takeaway
WackoPicko is the strongest alternative in this group for a scanner-evaluation hold-out, provided its legacy runtime is made reproducible. Pikachu is a useful broad supplementary PHP lab, but upstream explicitly marks it asleep. These are research recommendations, not claims that either application has been installed or tested here.

### Cited Findings
- **WackoPicko** is the original researcher's vulnerable PHP application used for the paper “Why Johnny Can't Pentest.” Its repository is MIT licensed and supplies source, a Dockerfile and upstream image instructions. [Repository](https://github.com/adamdoupe/WackoPicko)
- Its documented cases include reflected/stored XSS, SQL injection, command injection and directory traversal; the README names affected endpoints and parameters, supplies ordinary/admin test accounts, and describes multi-step and stored-input cases. It requires short PHP tags and deployment at the URL root. The README also contains historical Flash and null-byte file-inclusion exercises, so not every documented case should be assumed runnable in modern browsers/PHP. [README](https://raw.githubusercontent.com/adamdoupe/WackoPicko/master/README.markdown)
- WackoPicko's Dockerfile starts from `tutum/lamp`, installs `php5-gd` and configures `/etc/php5`; this is legacy packaging, not evidence of PHP 8 compatibility or present-day reproducible image builds. [Dockerfile](https://raw.githubusercontent.com/adamdoupe/WackoPicko/master/Dockerfile)
- Actual WackoPicko source shows `pictures/search.php` requiring several files, calling `Pictures::get_all_pictures_by_tag` with the request's `query` input, passing that input to `our_header`, and rendering it directly in a heading. This provides direct entry points plus helper/include relationships. [Search source](https://raw.githubusercontent.com/adamdoupe/WackoPicko/master/website/pictures/search.php)
- Its HTML helper further requires `users.php` and `functions.php`, and applies an `h()` wrapper at some output sites. Its users helper contains branch-dependent escaped/unescaped query construction in shared methods. These are useful inspection cases for contextual analysis, but should not be treated as universally safe decoys without reviewing `h()`, database configuration and reachable branches. [HTML helper](https://raw.githubusercontent.com/adamdoupe/WackoPicko/master/website/include/html_functions.php), [Users helper](https://raw.githubusercontent.com/adamdoupe/WackoPicko/master/website/include/users.php)
- **Pikachu** has an Apache-2.0 license, a Dockerfile and PHP source. [Repository](https://github.com/zhuifengshaonianhanlu/pikachu)
- Its Chinese README lists SQLi, XSS, command/code execution, file inclusion, unsafe downloads/uploads, traversal, insecure redirects, deserialization and SSRF. It documents PHP/MySQL setup, per-page hints and Docker options. Crucially, its opening notice explicitly calls the PHP platform old, marks the project asleep and directs users to a Java/Spring successor, MadRabbit. [README](https://raw.githubusercontent.com/zhuifengshaonianhanlu/pikachu/master/README.md)
- Pikachu's upstream Dockerfile uses a PHP 7 LAMP base and installs PHP 7.4 development tooling; modern PHP support should not be inferred. [Dockerfile](https://raw.githubusercontent.com/zhuifengshaonianhanlu/pikachu/master/Dockerfile)
- Actual Pikachu `vul/rce/rce_ping.php` includes a root-relative shared header, takes a POST input, selects an OS-dependent command operation, renders its result, and includes a shared footer. This is a compact end-to-end candidate for static candidate detection, form discovery and endpoint attribution. [Source](https://raw.githubusercontent.com/zhuifengshaonianhanlu/pikachu/master/vul/rce/rce_ping.php)
- **OWASP Bricks** is listed by OWASP VWAD as a PHP/MySQL open-source learning platform with login, upload and content exercises. Its canonical distribution is SourceForge, not an arbitrary GitHub mirror. The displayed newest release directory is Tuivai 2.2 dated November 30, 2013. [OWASP entry](https://vwad.owasp.org/app/bricks/), [Canonical files](https://sourceforge.net/projects/owaspbricks/files/)
- **Peruggia** is a PHP/MySQL image-gallery application listed by OWASP VWAD with GPLv2 licensing. Its canonical SourceForge files page displays Peruggia 1.2 and a directory modified in March 2010. [OWASP entry](https://vwad.owasp.org/app/peruggia/), [Files](https://sourceforge.net/projects/peruggia/files/)

### Inferences
- Reserve a reviewed subset of WackoPicko as a later hold-out after development against other labs. Its shared methods and stored/multi-step workflows test more than direct one-file patterns.
- WackoPicko's original source and runtime should be pinned together. Replacing obsolete database functions or changing the PHP version may change both line locations and exploitability, so patches must be documented as a separate benchmark variant.
- Pikachu offers broad category coverage including insecure redirects, but is a supplementary legacy lab rather than evidence our engine handles modern PHP frameworks.
- Bricks and Peruggia add historical diversity but are lower-priority than actively packaged alternatives: their age adds setup work, and neither inspected canonical page established a maintained container workflow.
- A documented vulnerable endpoint is a useful starting point for a case manifest, not an exhaustive answer key. Review and reproduce each selected case before scoring recall or declaring unlisted findings false.

### Gaps
- No apps were executed, containers pulled or images built. Docker availability, architecture support and current build success remain unverified.
- Exact latest commit dates were not reliably displayed for all repositories; do not equate a recent crawler timestamp with maintenance activity.
- Bricks' exact distribution license file and compatibility bounds were not inspected. Treat its OWASP open-source description as verified but avoid inventing a license identifier.

## Which benchmarks help validate the custom PHP analysis?

### Takeaway
NIST SARD supplies real PHP synthetic suites with documented case metadata; they complement complete apps and help test safe/unsafe classification. Do not call them PHP Juliet or treat thousands of microcases as thousands of realistic app vulnerabilities.

### Cited Findings
- SARD's suite catalog distinguishes Juliet Java, C/C++ and C# suites from its separately named PHP suites. [NIST catalog](https://samate.nist.gov/SARD/test-suites?o=desc&s=name)
- **Suite 103: PHP Vulnerability Test Suite** contains 42,212 generated PHP cases, is dated October 27, 2015, and covers categories including XSS, SQL injection and URL redirection. The case list includes “candidate good” and “candidate bad” metadata, including prepared-query and sanitization variations. [Suite 103](https://samate.nist.gov/SARD/test-suites/103)
- **Suite 114: PHP test suite – XSS, SQLi 1.0.0** contains 248,592 cases, dated May 12, 2022, with a 931 MB download. Its displayed cases include CWE-79/CWE-89, candidate-good/bad labels and source, sanitization, data-flow, context and sink descriptions. Despite the page's short description mentioning SQLi only, its title and displayed entries include XSS. [Suite 114](https://samate.nist.gov/SARD/test-suites/114)
- **Suite 115: PHP test suite – data flow 1.0.0** contains 20 synthetic XSS cases, dated August 2, 2022. Listed data-flow mechanisms include `global_variable`, `return_reference`, `call_user_func_array`, magic accessors, dynamic function calls and reflection. The displayed cases are candidate bad, so do not describe this particular suite as a balanced safe/unsafe corpus. [Suite 115](https://samate.nist.gov/SARD/test-suites/115)
- **SQLi-Labs** is a PHP/MySQL exercise collection covering GET/POST inputs, error/boolean/time-based SQLi, headers/cookies and second-order cases. Its README documents manual database setup and numbered lessons. [Original README](https://raw.githubusercontent.com/Audi-1/sqli-labs/master/readme.md)
- Its actual first lesson includes a separate database connection file, assigns request input to a variable and builds a query using legacy `mysql_*` functions. [Lesson source](https://raw.githubusercontent.com/Audi-1/sqli-labs/master/Less-1/index.php)
- A separate community fork explicitly updates the source for PHP 7 by replacing `mysql_*` functions with `mysqli_*`. This is not the original upstream project. [PHP 7 fork](https://github.com/skyblueee/sqli-labs-php7)

### Inferences
- Start with a small, reviewed subset of suite 103 or 114 for safe/unsafe correctness and suite 115 for difficult PHP semantics. The generated corpus size is no reason to run every case during a hackathon.
- SQLi-Labs is a focused DAST-regression target rather than a four-category application benchmark. Exact source provenance and runtime should be recorded when selecting a compatibility fork.
- Benchmark labels and comments must not become detection shortcuts. Select cases based on their actual semantics and keep evaluation cases separate from rule development.

### Gaps
- Downloads were not inspected or executed; manifests, redistribution terms, execution harness requirements and per-case dependencies still need review before bundling these suites.
- No explicit standalone license was evident in the inspected SQLi-Labs root; source availability alone should not be represented as a verified permissive open-source license.

## Which tempting candidates should be excluded or deferred?

### Takeaway
Language, transport and license mismatches matter. Some search hits are valuable for a later stage but do not meet a first PHP HTTP-based open-source benchmark requirement.

### Cited Findings
- **Yavuzlar/VulnLab** documents Docker setup and broad vulnerabilities including SQLi, XSS, command injection and traversal. Its Dockerfile installs PHP/Apache/MariaDB on Ubuntu 20.04. However, the actual LICENSE.md says CC BY-NC-SA 4.0 while the Dockerfile labels MPL 2.0. Report the conflict rather than presenting it as unqualified open source. [Repository](https://github.com/Yavuzlar/VulnLab), [License](https://raw.githubusercontent.com/Yavuzlar/VulnLab/main/LICENSE.md), [Dockerfile](https://raw.githubusercontent.com/Yavuzlar/VulnLab/main/Dockerfile)
- **OWASP Damn Vulnerable Web Sockets** is genuinely PHP: Ratchet with MySQL, MIT licensed, deliberately using WebSockets for application communication. [OWASP project](https://owasp.org/projects/damn-vulnerable-web-sockets), [Repository](https://github.com/interference-security/DVWS)
- **OWASP VulnerableApp** is Java, with a JAR standalone deployment and a Java language designation on its OWASP project page. It is not a PHP application despite covering attractive vulnerability categories. [OWASP project](https://owasp.org/projects/vulnerableapp)
- **OWASP Juice Shop** is cataloged as TypeScript/JavaScript with Node.js/Express; **WAVSEP** is Java. They are not PHP SAST benchmarks. [OWASP directory](https://vwad.owasp.org/)
- The old OWASP Benchmark repository redirects to BenchmarkJava. Do not infer a PHP edition from the generic name. [Repository](https://github.com/OWASP/Benchmark)

### Inferences
- Defer DVWS until WebSocket discovery, message inputs and attribution are explicitly in scope; ordinary HTTP parameter testing will not cover its central design.
- Defer VulnLab as a recommended redistributable open-source fixture until its licensing is clarified. It may remain a source-available candidate to investigate separately.
- Keep Java apps for the later language expansion instead of counting them toward present PHP validation.

### Gaps
- This search found no verified PHP edition of OWASP VulnerableApp or OWASP Benchmark; this is a scoped negative finding, not a claim no new project can exist.

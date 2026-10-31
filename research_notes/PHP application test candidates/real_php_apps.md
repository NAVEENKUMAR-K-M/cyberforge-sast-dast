# Real PHP applications and historical vulnerability pairs

## Which real applications make defensible later-stage tests?

### Takeaway
Recommend two narrowly selected, historical before/after tests after the training labs: phpMyAdmin for SQL injection and osTicket for reflected XSS. These are recommendations from source inspection, not claims that the engine detects them or that their old runtime environments have been successfully started. A third phpMyAdmin file-inclusion case has an existing Vulhub Compose fixture.

### Cited Findings
- **phpMyAdmin is a real PHP MySQL/MariaDB administration web application**, with upstream source and a GPL-2.0 license indication. [Repository](https://github.com/phpmyadmin/phpmyadmin)
- **CVE-2020-26935 / PMASA-2020-6:** upstream describes SQL injection in the search feature. Affected branches are 4.9.x before 4.9.6 and 5.0.x before 5.0.3. Upstream explicitly links fix commit `d09ab9bc9d634ad08b866d42bb8c4109869d38d2`. Candidate release pairs are **4.9.5 → 4.9.6**, or **5.0.2 → 5.0.3**. [Vendor advisory](https://www.phpmyadmin.net/security/PMASA-2020-6/)
- The actual fix affects `libraries/classes/Controllers/Table/TableSearchController.php` plus `js/tbl_zoom_plot_jqplot.js`. In the pre-fix method `getDataRowAction`, POST input `where_clause` reaches a constructed SELECT statement. The patch adds SQL-query-signature verification before proceeding; it also arranges for signatures to travel with the returned SQL clause. This is useful because the protection is not simply an escaping function. [Upstream fix diff](https://github.com/phpmyadmin/phpmyadmin/commit/d09ab9bc9d634ad08b866d42bb8c4109869d38d2)
- Upstream provides an official Docker project supporting Apache and FPM variants, MySQL/MariaDB connections, credentials and patch-version image tags. This establishes a supported containerisation approach, but old exact image availability/architecture was not execution-tested here. [Official Docker repository](https://github.com/phpmyadmin/docker)
- The 4.9.6/5.0.3 announcement confirms the security fixes and explicitly documents PHP-before-7.4/MySQL8 authentication compatibility pitfalls. Therefore pin the PHP/database combination as well as the application version. [Release announcement](https://www.phpmyadmin.net/news/2020/10/10/phpmyadmin-496-and-503-are-released/)
- **osTicket is a real open-source support-ticket application**, with PHP source, `include` and staff-facing application areas, and GPL-2.0 license indication. [Repository](https://github.com/osTicket/osTicket)
- **CVE-2023-1315:** NIST's record describes reflected XSS in osTicket prior to 1.16.6 and links the upstream fix. A candidate release pair is **1.16.5 → 1.16.6**; alternatively use the exact patch-parent and patched commit for the narrow regression. [NIST CVE record](https://nvd.nist.gov/vuln/detail/CVE-2023-1315)
- The upstream patch `ec6043935b4e30b5c0dfa544e256717182808a2e`, titled “xss: Search parent_id”, adds integer conversion for `parent_id`/`pid` in `include/ajax.search.php` and for the parent ID in `include/staff/templates/advanced-search.tmpl.php`. It explicitly identifies the XSS and provides a two-file, input-to-template regression target. [Upstream patch](https://github.com/osTicket/osTicket/commit/ec6043935b4e30b5c0dfa544e256717182808a2e)
- osTicket's 1.16.6 release includes that exact patch in its security changes. [Upstream release](https://github.com/osTicket/osTicket/releases/tag/v1.16.6)
- Upstream installation is web-based and requires a PHP-capable webserver and database. Current documentation's PHP requirements apply to current releases, not automatically to 1.16.x. Historical docs are available. [Current installation docs](https://docs.osticket.com/en/latest/Getting%20Started/Installation.html), [1.16.4 documentation](https://docs.osticket.com/en/v1.16.4/)

### Inferences
- **Priority 1 realistic test: phpMyAdmin SQLi.** It exercises object-oriented PHP, request routing into a controller and an application-specific protection. A scanner that only recognises built-in sanitisers may flag the fixed version too; the pair is valuable for measuring that limitation.
- **Priority 2 realistic test: osTicket XSS.** It exercises authenticated staff functionality and code split across a handler and template. The exact fix is simple enough to assess manually, but reaching the relevant workflow requires login and likely application state. Verify browser execution rather than merely string reflection.
- Neither is a substitute for the broad four-vulnerability-type lab benchmark. Start with one known issue per app; do not promise whole-application recall.
- A fixed version is a negative control **for the specific patched vulnerability**, not a claim that the entire version is safe.
- For exact code attribution, source used by SAST must match the files actually deployed. Version labels alone are weaker than a pinned source tree plus deployment metadata.

### Gaps
- No application was installed, started, scanned or exploited in this research.
- Old Docker-tag availability, Apple Silicon support, dependency download availability and legacy runtime startup were not verified.
- Exact browser/session steps and database seed data for the two regression cases still need to be independently validated locally.
- Historical osTicket 1.16.x PHP requirements were not established from a successfully retrieved version-pinned README; current requirements must not be copied blindly.

## How useful is Vulhub for this engine?

### Takeaway
Vulhub can reduce the effort of reproducing a specific historical issue. It is an environment collection, not a complete source-code correlation benchmark or answer key.

### Cited Findings
- Vulhub describes itself as a collection of pre-built vulnerable environments based on Docker Compose and lists an MIT license for its repository. The collection contains PHP-related product environments as well as many unrelated technologies. The target application's own license remains separate. [Vulhub repository](https://github.com/vulhub/vulhub)
- The phpMyAdmin CVE-2018-12613 fixture contains documentation, Compose and configuration, rather than a full checkout of the application. [Fixture directory](https://github.com/vulhub/vulhub/tree/master/phpmyadmin/CVE-2018-12613)
- That fixture pins `vulhub/phpmyadmin:4.8.1`, uses MySQL5.5, and publishes an HTTP port. Its only displayed bind mount is the supplied phpMyAdmin configuration. [Compose source](https://github.com/vulhub/vulhub/blob/master/phpmyadmin/CVE-2018-12613/docker-compose.yml)
- The vendor identifies CVE-2018-12613 as file inclusion caused by page-loading/whitelist validation. Versions 4.8.0 and 4.8.1 are affected and 4.8.2 fixes it. Authentication is ordinarily needed, with specific configuration-dependent exceptions; restrictive `open_basedir` mitigates impact. The advisory provides exact patch `7662d02939fb3cf6f0d9ec32ac664401dcfe7490`. [Vendor advisory](https://www.phpmyadmin.net/security/PMASA-2018-4/)
- The 4.8.2 archive page documents historical compatibility as PHP5.5–7.2 and MySQL/MariaDB5.5+. [Historical release](https://www.phpmyadmin.net/files/4.8.2/)

### Inferences
- **Optional third case:** phpMyAdmin4.8.1 →4.8.2, specifically file inclusion. Use harmless local file-read evidence rather than any code-execution objective.
- This exercises include/path reasoning, but do not silently label every file inclusion as CWE-22 path traversal. Preserve the mechanism and map CWE deliberately; the old vendor advisory uses broad CWE-661 rather than the PRD's precise taxonomy.
- Scanning only the Vulhub fixture directory would scan configuration, not the vulnerable application. Acquire matching upstream source or the actual deployed source tree for the SAST half.
- Some environments reproduce flaws in the PHP interpreter, webserver or dependencies rather than first-party PHP application logic. Those are unsuitable as primary evidence that our source-to-runtime app correlation works.

### Gaps
- Runtime startup and availability of old images were not checked. The fixture's default published-port configuration should be adapted to the local-only scope before actual use.

## Which alternatives should be deferred, and how should ground truth be defined?

### Takeaway
Avoid choosing a large business app simply because it has many CVEs. Select a known version, exact issue and patch, then validate that one case. Do not infer whole-app safety or a total vulnerability count from published advisories.

### Cited Findings
- **Dolibarr** is a plausible later complexity test: an upstream advisory describes `lt1` input in `societe/card.php` flowing to `localtax1_value` in `societe/class/societe.class.php`, tested on23.0.0 with official Docker/MariaDB10.11. However the advisory explicitly lists **no patched version**, despite a concrete affected range. It therefore does not currently provide the neat verified vulnerable/fixed pair desired for this shortlist. [Upstream advisory GHSA-v5fq-cf5m-vwv7](https://github.com/Dolibarr/dolibarr/security/advisories/GHSA-v5fq-cf5m-vwv7)
- Dolibarr's upstream security policy distinguishes intentional rich-content features from accepted XSS issues and makes configuration significant. That demonstrates why pattern hits alone do not define ground truth. [Upstream security policy](https://github.com/Dolibarr/dolibarr/security)

### Inferences
- WordPress/plugins, Drupal and major commerce frameworks should be deferred until the engine's supported routing, hooks and framework semantics justify their setup cost. This is scope advice, not a claim that these applications lack usable cases.
- Maintain a case record: app/version/commit, source hash, runtime configuration, authenticated role, endpoint/method/input, expected source location, expected evidence, fixed counterpart and manually verified outcome.
- Count successful links against this assessed case set. Do not count undocumented findings as false positives without assessment, or use an upstream CVE list as a complete app-wide answer key.

### Gaps
- No equally well-verified WordPress, Drupal, osCommerce/OpenCart or Laravel before/after pair was established within this research pass. Do not recommend arbitrary old versions as if reproducibility and relevance were proven.

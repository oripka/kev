// Note: Operating system patterns now distinguish client vs. server OS variants.
// Do not assume all OS vulnerabilities are server-side — use context from description.

import type {
  KevDomainCategory,
  KevEntry,
  KevExploitLayer,
  KevVulnerabilityCategory,
} from "~/types";

export type KevBaseEntry = Omit<
  KevEntry,
  "domainCategories" | "exploitLayers" | "vulnerabilityCategories" | "timeline"
>;

const internetEdgeDomainHints: KevDomainCategory[] = [
  "Networking & VPN",
  "Web Applications",
  "Web Servers",
  "Mail Servers",
  "Cloud & SaaS",
  "Security Appliances",
];

const matchesAny = (value: string, patterns: RegExp[]) =>
  patterns.some((pattern) => pattern.test(value));

type CvssVectorTraits = {
  attackVector?: "P" | "L" | "A" | "N";
  privilegesRequired?: "N" | "L" | "H";
  userInteraction?: "N" | "R";
};

const parseCvssVector = (vector?: string | null): CvssVectorTraits | null => {
  if (!vector) {
    return null;
  }

  const metrics: Record<string, string> = {};
  const tokens = vector.trim().split("/");

  for (const token of tokens) {
    const [metric, value] = token.split(":");
    if (!value) {
      continue;
    }

    const upperMetric = metric.toUpperCase();
    if (upperMetric === "AV" || upperMetric === "PR" || upperMetric === "UI") {
      metrics[upperMetric] = value.toUpperCase();
    }
  }

  if (!metrics.AV && !metrics.PR && !metrics.UI) {
    return null;
  }

  return {
    attackVector: metrics.AV as CvssVectorTraits["attackVector"] | undefined,
    privilegesRequired: metrics.PR as
      | CvssVectorTraits["privilegesRequired"]
      | undefined,
    userInteraction: metrics.UI as
      | CvssVectorTraits["userInteraction"]
      | undefined,
  };
};

// --- Primary edge / perimeter products (VPNs, gateways, ADCs, secure access) ---
const edgeStrongProductPatterns: RegExp[] = [
  // Citrix / Netscaler family
  /\b(?:citrix (?:adc|netscaler|gateway|workspace|access gateway)|netscaler)\b/i,

  // Ivanti / Pulse Secure / Connect Secure / Policy Secure
  /\b(?:pulse (?:secure|connect secure)|ivanti (?:connect secure|policy secure|secure access))\b/i,

  // Palo Alto Networks
  /\bglobalprotect\b/i,
  /\bpan[-\s]?os\b/i,

  // Fortinet products
  /\bforti(?:gate|os|web|proxy|wan|manager|analyzer)\b/i,

  // F5 Networks / BIG-IP / TMOS
  /\b(?:big[-\s]?ip|f5\s*(?:big[-\s]?ip|traffic manager|advanced waf|asm|ltm|gtm|tmos))\b/i,

  // Zscaler / Barracuda / SonicWall / Check Point
  /\bzscaler\b/i,
  /\bbarracuda (?:cloudgen|ssl[-\s]?vpn|remote access|firewall)\b/i,
  /\bsonicwall(?: ssl[-\s]?vpn| mobile connect)?\b/i,
  /\bcheck\s?point(?: firewall| gateway| vpn)?\b/i,

  // Cisco family (ASA, AnyConnect, Secure Firewall)
  /\bcisco (?:asa|anyconnect|secure (?:desktop|firewall|vpn)|adaptive security appliance)\b/i,
  /\bsecure mobile access\b/i,

  // Microsoft remote access and email edge services
  /\bremote desktop (?:gateway|web access|connection broker)\b/i,
  /\brd\s?(?:gateway|web|connection)\b/i,
  /\b(?:microsoft )?exchange (?:server|online|service)?\b/i,
  /\boutlook web access\b|\bowa\b/i,

  // Other edge products
  /\b(?:beyondtrust|privileged remote access|remote support)\b/i,
  /\b(?:cloudgenix|prisma access|panorama)\b/i,
  /\b(?:watchguard|sangfor|sonicwall|sophos xg|forticlient)\b/i
];

// --- Secondary / supporting web-facing or collaboration products often exposed on edge ---
const edgeSupportingProductPatterns: RegExp[] = [
  // Collaboration and dev tools
  /\b(?:sharepoint|jira|confluence|bitbucket|gitlab|github enterprise|atlassian)\b/i,

  // Workspace / endpoint management
  /\bworkspace one\b/i,
  /\bvmware horizon\b/i,
  /\bcitrix workspace\b/i,

  // Generic VPN portal references
  /\bvpn (?:portal|gateway|interface|web (?:portal|login|ui))\b/i,

  // Remote collaboration / content systems
  /\b(?:nextcloud|owncloud|mattermost|rocket\.chat|msteams|teams web)\b/i,

  // Web management and configuration interfaces
  /\bweb management (?:portal|interface|console)\b/i
];

// --- Patterns indicating network edge / externally reachable services ---
const edgeContextPatterns: RegExp[] = [
  // VPN / remote access
  /\bssl[-\s]?vpn\b/i,
  /\bclientless\s+vpn\b/i,
  /\bvpn (?:portal|gateway|service|interface|server)\b/i,
  /\bremote (?:access|portal|service|authentication|desktop|gateway|connection)\b/i,
  /\b(?:rd\s?web|rdweb|remote desktop (?:web|gateway|service|protocol))\b/i,

  // Internet-exposed / edge terms
  /\b(?:internet[-\s]?facing|public[-\s]?facing|externally accessible|exposed (?:to|on) the internet|public endpoint|external interface)\b/i,
  /\bedge (?:device|gateway|service|controller)\b/i,

  // Citrix / remote gateway / ADC
  /\b(?:citrix (?:gateway|netscaler|adc|access gateway)|netscaler|adc)\b/i,

  // WebVPN and remote web interfaces
  /\bwebvpn\b/i,
  /\bvpn web (?:portal|interface|login)\b/i,

  // Microsoft remote access and mail
  /\b(outlook web access|owa|exchange web services|ews)\b/i,
  /\bexchange (?:server|online|service)\b/i,

  // Other popular remote access / edge products
  /\b(pulse connect secure|globalprotect|fortigate ssl[-\s]?vpn|sonicwall ssl[-\s]?vpn|cisco asa|zscaler|anyconnect)\b/i,
  /\b(remote support|privileged remote access|beyondtrust)\b/i
];

// --- Patterns for web-based edge portals / login interfaces ---
const edgePortalPatterns: RegExp[] = [
  /\bweb (?:portal|login|interface|console|client|ui)\b/i,
  /\bportal (?:access|login|interface|dashboard)\b/i,
  /\bremote portal\b/i,
  /\bvpn web (?:portal|interface|login)\b/i,
  /\b(edge|internet)[-\s]?portal\b/i,
  /\b(access (?:portal|gateway))\b/i
];

// --- Patterns related to mail / Exchange / OWA edge services ---
const edgeMailPatterns: RegExp[] = [
  /\bmicrosoft exchange\b/i,
  /\bexchange (?:server|online|web services|service)\b/i,
  /\b(outlook web access|owa)\b/i,
  /\bexchange web services\b|\bews\b/i,
  /\b(mail web portal|mail (?:interface|gateway|service))\b/i
];

const webProductPatterns: RegExp[] = [
  // --- CI/CD, DevOps, developer tools ---
  /\bjenkins\b/i,
  /\bphpmailer\b/i,
  /\b(?:gitlab|gitbucket|gitea|bitbucket|github enterprise)\b/i,
  /\b(?:confluence|jira|crowd|bamboo)\b/i,
  /\b(?:langflow|projectsend|simplehelp)\b/i,

  // --- Apache / Java web stacks ---
  /\bapache (?:struts|ofbiz|roller|felix|cordova|airflow)\b/i,
  /\b(?:weblogic|websphere|glassfish|wildfly|jboss|tomcat|catalina)\b/i,
  /\bspring (?:boot|framework|cloud|data|security|mvc|core|commons)\b/i,

  // --- Web CMS / e-commerce platforms ---
  /\b(?:wordpress|drupal|joomla|magento|opencart|prestashop|woocommerce|typo3|umbraco|dotcms)\b/i,
  /\b(?:liferay|alfresco|sitecore|strapi|sharepoint)\b/i,
  /\b(?:adobe experience manager|aem forms|aem)\b/i,

  // --- Reporting / BI / analytics ---
  /\b(?:grafana|kibana|splunk|tableau|superset|qlik\s*sense|jasperreports|bi publisher)\b/i,

  // --- Enterprise apps / middleware / ERP / CRM ---
  /\b(?:sap (?:portal|netweaver|commerce|hybris)|netweaver|e[-\s]?business suite|ebs)\b/i,
  /\b(?:oracle fusion|oracle weblogic|progress wh?atsup gold|whatsup gold)\b/i,
  /\b(?:commvault.*command center|command center)\b/i,
  /\b(?:manageengine|servicedesk|adselfservice|opmanager|desktop central|endpoint manager)\b/i,
  /\b(?:sysaid|cityworks|veracore)\b/i,

  // --- Security / remote access / VPN / gateways ---
  /\b(?:pulse connect secure|connect secure|policy secure)\b/i,
  /\b(?:fortinet|fortiweb|fortios|fortigate)\b/i,
  /\b(?:sonicwall|sonicos)\b/i,
  /\b(?:beyondtrust|privileged remote access|remote support)\b/i,
  /\b(?:cisco ise|identity services engine|cisco asa|adaptive security appliance)\b/i,
  /\b(?:vpn (?:appliance|portal)|webvpn|cloud services appliance|csa)\b/i,
  /\b(?:velo?cloud|sd[-\s]?wan (?:edge|orchestrator|controller)|aviatrix|n[-\s]?central)\b/i,

  // --- Monitoring / IT infrastructure ---
  /\b(?:phpmyadmin|cacti|zabbix|nagios|pfsense|opennms|prometheus|graylog)\b/i,
  /\b(?:progress.*whatsup gold|whatsup gold)\b/i,

  // --- Web / mail services ---
  /\b(?:zimbra|roundcube|webmail|owa|outlook web|exchange (?:server)?|proxylogon|mdaemon)\b/i,
  /\b(?:coldfusion|rails|jquery|imagemagick|flash player|adminer)\b/i,

  // --- Devices / appliances / firmware-exposed products ---
  /\b(?:ip camera|nvr|dvr|webcam|nas|geovision|draytek|vigor[0-9]+|tp[-\s]?link|tplink|archer|d[-\s]?link|sophos)\b/i,

  // --- Misc enterprise products ---
  /\b(?:apex one|telemessages?|n[-\s]?central|goanywhere|crushftp)\b/i
];

// --- Web server / application container patterns ---
const webServerPatterns: RegExp[] = [
  // Apache family
  /\bapache(?: http server| httpd)?\b/i,
  /\bhttpd\b/i,

  // Nginx, Caddy, OpenResty
  /\bnginx\b/i,
  /\bcaddy\b/i,
  /\bopenresty\b/i,

  // Microsoft IIS / Internet Information Services
  /\b(?:internet information services|microsoft iis|\biis\b)\b/i,

  // Java / servlet containers
  /\bapache tomcat\b|\btomcat\b|\bcatalina\b/i,
  /\bjetty\b/i,
  /\bglassfish\b/i,
  /\bwildfly\b/i,
  /\bjboss\b/i,
  /\bresin server\b/i,
  /\bweblogic\b/i,
  /\bwebsphere\b/i,

  // Lightweight or embedded servers
  /\blighttpd\b/i,
  /\bcherokee\b/i,
  /\bmongoose server\b/i,
  /\bboa server\b/i,
  /\bminihttpd\b/i
];

// --- Devices / appliances / embedded web interfaces ---
const webDevicePatterns: RegExp[] = [
  // Cameras, recorders, NAS, webcams
  /\b(ip camera|nvr|dvr|webcam|nas|network[-\s]?storage|surveillance camera)\b/i,

  // Routers, gateways, Wi-Fi controllers, firewalls, VPNs
  /\b(router|gateway|access point|wireless controller|firewall|ap|repeater|range extender)\b/i,

  // Appliances and embedded devices
  /\b(security appliance|vpn appliance|load[-\s]?balancer|proxy appliance|edge device)\b/i,
  /\b(printer|mfp|copier|print server)\b/i,
  /\b(iot device|smart[-\s]?(plug|camera|lock|switch|tv))\b/i,
  /\b(network[-\s]?attached device|industrial control|plc|scada)\b/i
];

// --- Negative (browser / client app) patterns ---
// Used to filter out mentions that should NOT trigger "web server" detection.
const webNegativePatterns: RegExp[] = [
  /\binternet explorer\b/i,
  /\bgoogle chrome\b/i,
  /\bmozilla firefox\b/i,
  /\bmicrosoft edge\b/i,
  /\bapple safari\b/i,
  /\bbrave\b/i,
  /\bopera(?: mini| gx)?\b/i,
  /\bvivaldi\b/i,
  /\bduckduckgo browser\b/i,
  /\bedge(?: chromium)?\b/i,
  /\bmobile safari\b/i,
  /\bandroid browser\b/i,
  /\biphone browser\b/i,
  /\bbrowser\b/i
];
// --- Web indicators of attack types or exploit primitives ---
const webIndicatorPatterns: RegExp[] = [
  // Injection and scripting
  /\bcross[-\s]?site scripting\b|\bxss\b/i,
  /\bxml external entity\b|\bxxe\b/i,
  /\bserver[-\s]?side request forgery\b|\bssrf\b/i,
  /\bsql injection\b|\bsqli\b/i,
  /\b(command|os)[-\s]?injection\b/i,
  /\btemplate[-\s]?injection\b|\b(twig|freemarker|jinja2|handlebars|velocity)\b/i,

  // File traversal / inclusion / upload
  /\b(directory|path)[-\s]?traversal\b/i,
  /(?:\.\.\/){1,}/i,
  /\b(remote|local) file inclusion\b|\brfi\b|\blfi\b/i,
  /\b(arbitrary (?:file|code) upload|file (?:upload|download|overwrite|replace))\b/i,

  // Redirects / deserialization / misc
  /\b(open|url)[-\s]?redirect\b/i,
  /\bdeserialization\b|\bserialized object\b/i,
  /\bprototype pollution\b/i,
  /\bcross[-\s]?site request forgery\b|\bcsrf\b/i,

  // Script / dynamic web extension indicators
  /\.(?:php\d*|jsp|asp|aspx|cgi|pl|js|py|rb|lua|cfm)\b/i,
  /\/[a-z0-9._-]+\/[a-z0-9._-]+\.(?:php|jsp|asp|aspx|cgi|pl|js|py|rb|cfm)\b/i,

  // VPN / web portals / embedded web services
  /\bwebvpn\b/i,
  /\bclientless vpn\b/i
];

// --- Web application / service context (strong indicators) ---
const webStrongContextPatterns: RegExp[] = [
  // web interfaces, consoles, dashboards
  /\bweb (?:interface|console|ui|portal|application|service|dashboard|admin|client)\b/i,
  /\bmanagement (?:interface|portal|console|ui|plane|dashboard|panel)\b/i,
  /\badmin(?:istrator)? (?:interface|portal|console|ui|dashboard|panel)\b/i,
  /\badministrative (?:interface|portal|console|ui|dashboard|panel)\b/i,
  /\bsuper[-\s]?admin\b/i,
  /\b(control (?:panel|plane|center))\b/i,
  /\blogin (?:portal|page|interface|screen|panel)\b/i,
  /\bserver url\b/i,
  /\b(parental control page|browser[-\s]?based|web[-\s]?based|web content)\b/i,

  // HTTP / HTTPS / request/response context
  /(?:via|over)\s+https?/i,
  /https?:\/\//i,
  /\bhttp\b[^.]{0,40}\b(request|response|endpoint|header|parameter|query)\b/i,
  /\bhttps?\s*(?:request|requests|response|responses)\b/i,
  /\bcrafted[^.]{0,40}https?\b/i,

  // server components
  /\bcgi[-/]bin\b/i,
  /\b\/userRpm\/\b/i,
  /\bhttp post (?:request|handler)\b/i,
  /\bhttpd\b|\bweb server\b|\bvpn web server\b/i,

  // APIs and protocols
  /\b\/[a-z0-9_-]*api\b/i,
  /\b(rest|graphql|soap|json[-\s]?rpc)\s+api\b/i,
  /\bapi (?:request|response|endpoint|call|gateway)\b/i,
  /\b(?:get|post|put|delete|patch)\s+requests?\b/i,

  // Misc portal / VPN terms
  /\bwebvpn\b/i,
  /\b(vpn (?:web )?portal)\b/i
];

// --- Web interface context often found in embedded / device products ---
const webDeviceContextPatterns: RegExp[] = [
  /\b(web (?:interface|management|console)|browser)\b/i,
  /https?:\/\//i,
  /\bcrafted requests?\b/i,
  /\bhttp\b/i,
  /\bcgi\b/i,
  /\bweb[-\s]?ui\b/i,
  /\brouter web interface\b/i,
  /\bdevice (?:web|browser) portal\b/i
];

// --- Admin / management panel context ---
const webManagementPatterns: RegExp[] = [
  /\bmanagement (?:interface|portal|console|ui|plane|dashboard|panel)\b/i,
  /\badmin(?:istrator)? (?:interface|portal|console|ui|dashboard|panel)\b/i,
  /\badministrative (?:interface|portal|console|ui|dashboard|panel)\b/i,
  /\badmin(?:istrator)? account\b/i,
  /\bsuper[-\s]?admin\b/i,
  /\b(control panel|control plane|control center)\b/i,
  /\blogin (?:portal|page|interface|screen|panel)\b/i,
  /\bserver url\b/i,
  /\bwebvpn\b/i,
  /\bweb management interface\b/i,
  /\bconfiguration (?:page|portal|ui)\b/i
];

const webApiPatterns: RegExp[] = [
  // REST / Web / GraphQL / SOAP / JSON / gRPC
  /\brest(?:[-\s]?ful)?(?:[-\s]?api)?\b/i,
  /\bgraphql(?:[-\s]?api)?\b/i,
  /\bsoap(?:[-\s]?api)?\b/i,
  /\bjson(?:[-\s]?api)?\b/i,
  /\bweb[-\s]?api\b/i,
  /\bapi[-\s]?endpoint\b/i,
  /\bapi[-\s]?interface\b/i,
  /\bapi (?:request|response|call|gateway|server|client)\b/i,
  /(?:^|[^a-z0-9])\/api(?:\/[a-z0-9._~-]+)?\b/i,
  /\bgrpc\b/i,
  /\bopenapi\b/i,
  /\bswagger\b/i
];

const nonWebProductPatterns: RegExp[] = [
  // OS, low-level, or non-web subsystems
  /\b(kernel|driver|firmware|microcode|bootloader|hypervisor|bios|uefi)\b/i,
  /\b(common log file system|clfs)\b/i,
  /\bsandbox[-\s]?escape\b/i,
  /\b(microsoft management console|\bmmc\b)\b/i,
  /\b(directx|gdi|win32k|windows kernel|ntoskrnl|system driver)\b/i,
  /\b(printer driver|graphics driver|network driver)\b/i
];

const nonWebContextPatterns: RegExp[] = [
  /\bphysical access\b/i,
  /\b(local privilege escalation|locally|local user|local attacker)\b/i,
  /\b(stack[-\s]?based buffer overflow|heap[-\s]?based buffer overflow|buffer overflow|out[-\s]?of[-\s]?bounds|use[-\s]?after[-\s]?free|memory corruption)\b/i,
  /\b(command[-\s]?line interface|\bcli\b|shell access|console)\b/i,
  /\b(file system|filesystem|disk|volume)\b/i
];

const mailServerPatterns: RegExp[] = [
  /\b(?:microsoft )?exchange(?: server| online| web services| service)?\b/i,
  /\b(?:outlook web access|owa)\b/i,
  /\bpostfix\b/i,
  /\bsendmail\b/i,
  /\bqmail\b/i,
  /\bexim\b/i,
  /\b(?:smtp|imap|pop3)\b/i,
  /\bmail(?:\s+(?:server|gateway|transfer agent|transport agent|relay|appliance))?\b/i,
  /\bmailman\b/i,
  /\bzimbra\b/i,
  /\b(?:lotus|ibm) domino\b/i,
  /\bkerio connect\b/i,
  /\bicewarp\b/i,
  /\bmdaemon\b/i,
  /\bproofpoint\b/i,
  /\bmimecast\b/i,
  /\bironport\b/i,
  ...edgeMailPatterns,
];

const securityAppliancePatterns: RegExp[] = [
  ...edgeStrongProductPatterns,
  /\bnext[-\s]?generation firewall\b/i,
  /\bngfw\b/i,
  /\bweb application firewall\b/i,
  /\bwaf\b/i,
  /\bintrusion (?:detection|prevention) system\b/i,
  /\b(?:ids|ips)\b/i,
  /\b(?:secure web|email) gateway\b/i,
  /\bsecurity appliance\b/i,
  /\bthreat management gateway\b/i,
  /\bforti(?:gate|os|web|proxy|mail|manager|analyzer)\b/i,
  /\bpan[-\s]?os\b/i,
  /\bglobalprotect\b/i,
  /\bcheckpoint\b/i,
  /\bcheck\s?point\b/i,
  /\bsonicwall\b/i,
  /\bwatchguard\b/i,
  /\bzscaler\b/i,
  /\bbarracuda\b/i,
  /\bsophos (?:utm|xg|xgs|firewall)\b/i,
  /\bstormshield\b/i,
  /\btrend micro (?:tippingpoint|deep security)\b/i,
  /\bf5\s*(?:big[-\s]?ip|advanced waf|asm|ltm|gtm|tmos)\b/i,
  /\bcisco (?:firepower|secure firewall|asa|fmc)\b/i,
  /\bzero trust network access\b/i,
  /\bztna\b/i,
];

const networkingVpnPatterns: RegExp[] = [
  /\brouter\b/i,
  /\bswitch\b/i,
  /\bnetwork (?:device|appliance|controller|manager|monitor)\b/i,
  /\bgateway\b/i,
  /\b(?:vpn|vpn concentrator|vpn gateway|vpn appliance|vpn server)\b/i,
  /\bremote (?:access|gateway|desktop|vpn|client)\b/i,
  /\bsd[-\s]?wan\b/i,
  /\bwan (?:accelerator|optimizer|controller)\b/i,
  /\bload balancer\b/i,
  /\bapplication delivery controller\b/i,
  /\badc\b/i,
  /\bproxy (?:server|appliance|service)\b/i,
  /\b(?:wireless|wi[-\s]?fi) (?:controller|access point|ap)\b/i,
  /\b(?:firewall|edge device|customer premises equipment|cpe)\b/i,
  /\b(?:cisco|juniper|arista|mikrotik|ubiquiti|netgear|d-link|tp[-\s]?link|tplink|zyxel|draytek|peplink|silver peak|riverbed|versa networks|aruba os|extreme networks|big-ip|citrix adc|netscaler)\b/i,
  /\bpfsense\b/i,
  /\bopenvpn\b/i,
  /\bmeraki\b/i,
];

const browserPatterns: RegExp[] = [
  ...webNegativePatterns,
  /\bchromium\b/i,
  /\btor browser\b/i,
  /\bwaterfox\b/i,
  /\bseamonkey\b/i,
  /\bmaxthon\b/i,
  /\buc browser\b/i,
  /\bqq browser\b/i,
  /\byandex browser\b/i,
  /\bnaver whale\b/i,
  /\bvivaldi\b/i,
];

const webApplicationProductPatterns: RegExp[] = [
  /\bwordpress\b/i,
  /\bdrupal\b/i,
  /\bjoomla\b/i,
  /\bmagento\b/i,
  /\bopencart\b/i,
  /\bprestashop\b/i,
  /\bwoocommerce\b/i,
  /\btypo3\b/i,
  /\bumbraco\b/i,
  /\bdotcms\b/i,
  /\bsitecore\b/i,
  /\bstrapi\b/i,
  /\bcms\b/i,
  /\bconfluence\b/i,
  /\bjira\b/i,
  /\batlassian\b/i,
  /\bbitbucket\b/i,
  /\bgitlab\b/i,
  /\bgitea\b/i,
  /\bjenkins\b/i,
  /\bteamcity\b/i,
  /\bbamboo\b/i,
  /\bphpmailer\b/i,
  /\bphpmyadmin\b/i,
  /\badobe experience manager\b/i,
  /\baem\b/i,
  /\bcoldfusion\b/i,
  /\bgrafana\b/i,
  /\bkibana\b/i,
  /\bsplunk\b/i,
  /\btableau\b/i,
  /\bsuperset\b/i,
  /\bqlik\b/i,
  /\bmetabase\b/i,
  /\balfresco\b/i,
  /\bliferay\b/i,
  /\bsap (?:netweaver|portal|commerce|hybris)\b/i,
  /\boracle (?:weblogic|fusion middleware|webcenter)\b/i,
  /\bmanageengine\b/i,
  /\bservicedesk\b/i,
  /\bopmanager\b/i,
  /\bdesktop central\b/i,
  /\bendpoint manager\b/i,
  /\bwhats ?up gold\b/i,
  /\bcommvault\b/i,
  /\bcommand center\b/i,
  /\bnextcloud\b/i,
  /\bowncloud\b/i,
  /\bmattermost\b/i,
  /\brocket\.chat\b/i,
  /\bzulip\b/i,
  /\bgoanywhere\b/i,
  /\bcrushftp\b/i,
  /\bfilezilla server\b/i,
  /\bportal interface\b/i,
  /\bweb (?:application|app|console|client|ui|interface|management|portal)\b/i,
  /\bwebmail\b/i,
  /\bowa\b/i,
  /\boutlook web\b/i,
  /\bexchange web services\b/i,
  /\bcustomer portal\b/i,
  /\bself-service portal\b/i,
  /\bintranet portal\b/i,
];

const operatingSystemPatterns: RegExp[] = [
  // --- Client / Desktop Operating Systems ---
  /\bwindows (?:xp|vista|7|8(?:\.1)?|10|11)\b/i,
  /\bmac ?os(?: x)?\b/i,
  /\bmacos\b/i,
  /\bios\b/i,
  /\bipad ?os\b/i,
  /\bipados\b/i,
  /\bandroid\b/i,
  /\bchrome ?os\b/i,
  /\bchromeos\b/i,
  /\bwindows phone\b/i,

  // --- Server / Infrastructure Operating Systems ---
  /\bwindows server(?:\s*(?:2000|2003|2008|2012|2016|2019|2022)?)?\b/i,
  /\bwindows nt\b/i,
  /\bwin32k\b/i,
  /\bntoskrnl\b/i,
  /\bred hat enterprise linux\b/i,
  /\brhel\b/i,
  /\bcentos(?: stream)?(?: server)?\b/i,
  /\bfedora(?: server)?\b/i,
  /\bsuse(?: linux enterprise)?(?: server)?\b/i,
  /\bopensuse(?: leap| tumbleweed)?(?: server)?\b/i,
  /\bubuntu(?: server| lts)?\b/i,
  /\bdebian(?: server)?\b/i,
  /\boracle linux(?: server)?\b/i,
  /\bamazon linux(?: server)?\b/i,
  /\balma(?: ?linux)?(?: server)?\b/i,
  /\brocky(?: linux)?(?: server)?\b/i,
  /\bkali linux\b/i,
  /\bparrot os\b/i,
  /\blinux mint\b/i,
  /\barch linux\b/i,
  /\bmanjaro\b/i,
  /\bgentoo\b/i,
  /\bsolaris\b/i,
  /\baix\b/i,
  /\bhp-ux\b/i,
  /\btru64\b/i,
  /\birix\b/i,
  /\bsunos\b/i,
  /\b(?:free|open|net|dragonfly)bsd\b/i,
  /\bz\/os\b/i,
  /\bos\/400\b/i,
  /\bibm i\b/i,

  // --- Embedded / Real-Time OS ---
  /\bqnx(?: neutrino)?\b/i,
  /\bvxworks\b/i,
  /\bintegrity os\b/i,
  /\bfreertos\b/i,
  /\bthreadx\b/i,
  /\blynxos\b/i,
  /\bzephyr os\b/i,
  /\bblackberry os\b/i,
  /\bsymbian\b/i,
  /\btizen\b/i,
  /\bsailfish os\b/i,
];

const icsPatterns: RegExp[] = [
  /\bics\b/i,
  /\bscada\b/i,
  /\bplc\b/i,
  /\brtu\b/i,
  /\bhmi\b/i,
  /\bdcs\b/i,
  /\bindustrial (?:control|automation|system)\b/i,
  /\bprocess control\b/i,
  /\bsiemens\b/i,
  /\brockwell\b/i,
  /\ballen[-\s]?bradley\b/i,
  /\bschneider electric\b/i,
  /\babb\b/i,
  /\bomron\b/i,
  /\byokogawa\b/i,
  /\bmitsubishi electric\b/i,
  /\bemerson\b/i,
  /\bhoneywell\b/i,
  /\bge (?:digital|fanuc|proficy)\b/i,
  /\bbeckhoff\b/i,
  /\bbosch rexroth\b/i,
  /\bwago\b/i,
  /\bphoenix contact\b/i,
  /\binductive automation\b/i,
  /\bignition\b/i,
  /\bwonderware\b/i,
  /\baveva\b/i,
  /\bzenon\b/i,
  /\bopc\b/i,
  /\bmodbus\b/i,
  /\bprofinet\b/i,
  /\bethernet\/ip\b/i,
  /\biec[-\s]?104\b/i,
  /\biec[-\s]?60870\b/i,
  /\bdnp3\b/i,
];

const virtualizationContainerPatterns: RegExp[] = [
  /\bvmware\b/i,
  /\besxi\b/i,
  /\bvsphere\b/i,
  /\bvcenter\b/i,
  /\bworkstation\b/i,
  /\bfusion\b/i,
  /\bnsx\b/i,
  /\bhyper[-\s]?v\b/i,
  /\bscvmm\b/i,
  /\bxen(?:server| project)?\b/i,
  /\bcitrix (?:hypervisor|xen|virtual apps|virtual desktops)\b/i,
  /\bkvm\b/i,
  /\bqemu\b/i,
  /\blibvirt\b/i,
  /\bproxmox\b/i,
  /\bnutanix\b/i,
  /\bahv\b/i,
  /\bvirtualbox\b/i,
  /\bparallels\b/i,
  /\bdocker\b/i,
  /\bcontainerd\b/i,
  /\bcri[-\s]?o\b/i,
  /\bpodman\b/i,
  /\blxc\b/i,
  /\blxd\b/i,
  /\brunc\b/i,
  /\bkubernetes\b/i,
  /\bopenshift\b/i,
  /\brancher\b/i,
  /\bk3s\b/i,
  /\beks\b/i,
  /\baks\b/i,
  /\bgke\b/i,
  /\bnomad\b/i,
  /\bmesos\b/i,
  /\bdocker swarm\b/i,
  /\bopenstack\b/i,
  /\bcloudstack\b/i,
];

const cloudSaaSPatterns: RegExp[] = [
  /\baws\b/i,
  /\bamazon web services\b/i,
  /\bec2\b/i,
  /\bs3\b/i,
  /\biam\b/i,
  /\brds\b/i,
  /\bcloudfront\b/i,
  /\bazure\b/i,
  /\bmicrosoft (?:365|office 365|entra id|azure ad)\b/i,
  /\bexchange online\b/i,
  /\bsharepoint online\b/i,
  /\bonedrive\b/i,
  /\bgoogle (?:cloud|workspace|g suite|apps)\b/i,
  /\bgcp\b/i,
  /\bbigquery\b/i,
  /\bapp engine\b/i,
  /\bcloud run\b/i,
  /\bsalesforce\b/i,
  /\bservicenow\b/i,
  /\bworkday\b/i,
  /\bokta\b/i,
  /\bauth0\b/i,
  /\bduo security\b/i,
  /\bslack\b/i,
  /\bzoom\b/i,
  /\bbox\b/i,
  /\bdropbox\b/i,
  /\bgithub\b/i,
  /\bgitlab\b/i,
  /\batlassian cloud\b/i,
  /\bcloudflare\b/i,
  /\bfastly\b/i,
  /\bakamai\b/i,
  /\bvercel\b/i,
  /\bnetlify\b/i,
  /\bsoftware as a service\b/i,
  /\bsaas\b/i,
  /\bcloud (?:service|platform|application)\b/i,
];

const databaseStoragePatterns: RegExp[] = [
  /\bdatabase\b/i,
  /\bsql server\b/i,
  /\bmicrosoft sql\b/i,
  /\bmysql\b/i,
  /\bmariadb\b/i,
  /\bpostgres(?:ql)?\b/i,
  /\boracle database\b/i,
  /\bdb2\b/i,
  /\bsqlite\b/i,
  /\bfirebird\b/i,
  /\binformix\b/i,
  /\bsybase\b/i,
  /\bteradata\b/i,
  /\bsap hana\b/i,
  /\bsnowflake\b/i,
  /\bredshift\b/i,
  /\bbigquery\b/i,
  /\bdynamodb\b/i,
  /\bcosmos db\b/i,
  /\bmongodb\b/i,
  /\bcouchdb\b/i,
  /\bcouchbase\b/i,
  /\bredis\b/i,
  /\bmemcached\b/i,
  /\bcassandra\b/i,
  /\bneo4j\b/i,
  /\borientdb\b/i,
  /\belastic(?:search)?\b/i,
  /\bopensearch\b/i,
  /\bsolr\b/i,
  /\bdata (?:warehouse|lake|mart)\b/i,
  /\bstorage\b/i,
  /\bnas\b/i,
  /\bsan\b/i,
  /\bnetapp\b/i,
  /\bisilon\b/i,
  /\bpure storage\b/i,
  /\bemc\b/i,
  /\bpowerstore\b/i,
  /\bpowermax\b/i,
  /\b3par\b/i,
  /\bhpe primera\b/i,
  /\bhpe nimble\b/i,
  /\bhitachi vsp\b/i,
  /\bqnap\b/i,
  /\bsynology\b/i,
  /\biscsi\b/i,
  /\bfibre channel\b/i,
  /\bobject storage\b/i,
  /\btape library\b/i,
  /\bbackup appliance\b/i,
  /\bs3 bucket\b/i,
];

type DomainRuleCategory = Exclude<
  KevDomainCategory,
  "Internet Edge" | "Other" | "Non-Web Applications"
>;

const domainCategoryPatterns: Record<DomainRuleCategory, RegExp[]> = {
  "Mail Servers": mailServerPatterns,
  "Security Appliances": securityAppliancePatterns,
  "Networking & VPN": networkingVpnPatterns,
  Browsers: browserPatterns,
  "Web Applications": webApplicationProductPatterns,
  "Web Servers": webServerPatterns,
  "Operating Systems": operatingSystemPatterns,
  "Industrial Control Systems": icsPatterns,
  "Virtualization & Containers": virtualizationContainerPatterns,
  "Cloud & SaaS": cloudSaaSPatterns,
  "Database & Storage": databaseStoragePatterns,
};

const domainRules: Array<{
  category: KevDomainCategory;
  patterns: RegExp[];
}> = Object.entries(domainCategoryPatterns).map(([category, patterns]) => ({
  category: category as DomainRuleCategory,
  patterns,
}));

const privilegePatterns: RegExp[] = [
  /\b(privilege escalation|elevation of privilege|gain(?:s|ed)? (?:administrative|root|system|kernel|user|superuser) privileges?|eop|lpe)\b/i
];

const remoteExecutionPatterns: RegExp[] = [
  /\b(remote code execution|rce)\b/i,
  /\b(execute code remotely|remote execution|arbitrary remote code)\b/i,
  /\b(remote exploit|remote payload)\b/i
];

const codeExecutionPatterns: RegExp[] = [
  /\b(execute arbitrary code|arbitrary code execution|run arbitrary code|code[-\s]?execution|execute injected code)\b/i,
  /\b(arbitrary command execution|command injection)\b/i
];

const remoteContextPatterns: RegExp[] = [
  // remote actor context
  /\bremote (?:attacker|user|actor|threat|client|system|host)\b/i,
  /\bremote,?\s*(?:unauthenticated|authenticated)\s+attacker\b/i,
  /\bremotely\b/i,

  // network or protocol context
  /\b(over|across|via|through)\s+(?:the\s+)?network\b/i,
  /\b(network[-\s]?(?:based|accessible|reachable)|network access)\b/i,

  // specific protocols / transports
  /\b(?:http|https|smb|rpc|rdp|ftp|smtp|imap|pop3|dns|tcp|udp|ldap|snmp|modbus|dce\/?rpc|nfs|ssh|telnet|mqtt|coap)\b/i,

  // crafted request / packet / payload / traffic indicators
  /\bcrafted (?:request|packet|payload|network (?:request|traffic|message|packet))\b/i,
  /\bmalformed (?:packet|request|response|payload)\b/i,
  /\bnetwork (?:message|frame|datagram|stream)\b/i
];

// Enhanced and safer regexes to detect memory corruption vulnerabilities
const memoryCorruptionPatterns: RegExp[] = [
  // General memory corruption
  /\bmemory (?:corruption|corrupt(?:ed)?)\b/i,

  // Buffer overflows and similar
  /\b(?:buffer(?:[-\s]?(?:overflow|overrun|underflow|underrun))|stack(?:[-\s]?(?:overflow|overrun))|heap(?:[-\s]?(?:overflow|corruption)))\b/i,

  // Out-of-bounds — ensure bounded by non-word chars to avoid OOB inside words
  /(?:^|[^a-z0-9])(out[-\s]?of[-\s]?bounds|oob)(?: (?:read|write|access|r\/w|w\/r))?(?=[^a-z0-9]|$)/i,

  // Off-by-one
  /\boff[-\s]?by[-\s]?one(?: (?:overflow|read|write|error))?\b/i,

  // Use-after-free & pointer issues
  /\b(use[-\s]?after[-\s]?free|use[-\s]?after[-\s]?scope|double[-\s]?free|dangling (?:pointer|reference)|invalid pointer)\b/i,

  // Heap/stack corruption
  /\b(?:heap corruption|stack corruption|heap[-\s]?overflow|stack[-\s]?overflow)\b/i,

  // Write primitives and overwrite issues
  /\b(?:write[-\s]?(?:what[-\s]?where)|arbitrary write|controlled write|partial overwrite|wild write)\b/i,

  // Integer overflow / underflow
  /\b(?:integer (?:overflow|underflow)|signedness (?:error|issue))\b/i,

  // Format string vulns that cause memory corruption
  /\bformat[-\s]?string(?: vulnerability| bug)?\b/i,

  // Well-known exploit family names and primitives lacking explicit memory wording
  /\bkernel pool\b/i,
  /\b(?:eternal(?:blue|romance|synergy|champion)|doublepulsar|smbghost|coronablue|educatedscholar)\b/i,

];

const denialOfServicePatterns: RegExp[] = [
  // explicit denial-of-service phrases (keeps "dos" only when part of "dos attack" or as DDoS/DoS forms)
  /\b(?:denial[-\s]?of[-\s]?service|denial[-\s]?of[-\s]?service attack|dos attack)\b/i,
  /\b(?:ddo?s(?:[-\s]?attack)?|d\.?d\.?o\.?s)\b/i, // matches DDoS / DoS / D.D.O.S forms (but not generic 'dos' words when used in context)

  // resource exhaustion / leaks / allocation storms
  /\b(?:resource(?:[-\s]?exhaustion| exhaustion)|memory(?:[-\s]?exhaustion| exhaustion| leak| pressure)|out[-\s]?of[-\s]?memory|oom(?: killer)?\b)/i,
  /\b(?:cpu(?:[-\s]?exhaustion| exhaustion| spike| high(?:[-\s]?cpu| load)?)|high(?:[-\s]?cpu|[-\s]?load|[-\s]?utilization))\b/i,

  // crashes, panics, segfaults — kept as whole words to avoid noise
  /\b(?:crash(?:es|ed)?|panic(?:s)?|segmentation fault|segfault|kernel panic)\b/i,

  // hangs / unresponsive / infinite loops / busy/spin loops
  /\b(?:hang(?:s|ing)?|unresponsive|freeze|stuck|infinite(?:[-\s]?loop)?|busy(?:[-\s]?loop|loop)|spin(?:[-\s]?lock)?)\b/i,

  // flooding / request abuse / connection exhaustion / socket exhaustion / rate-limit bypass
  /\b(?:flood(?:ing|ed)?|request(?:[-\s]?flood|[-\s]?storm)?|connection(?:[-\s]?flood|[-\s]?exhaustion|[-\s]?storm)|socket(?:[-\s]?exhaustion)?)\b/i,
  /\b(?:rate[-\s]?limit(?:ing)? bypass|rate[-\s]?limit(?:ing)?|throttl(?:e|ing) bypass|throttle(?:ing)?)\b/i,

  // fork bombs, descriptor exhaustion, handle exhaustion
  /\b(?:fork[-\s]?bomb|file[-\s]?descriptor(?:[-\s]?exhaustion)?|fd(?:[-\s]?exhaustion)?|handle(?:[-\s]?exhaustion)?)\b/i,

  // patterns describing DoS cause (infinite accept loop, busy polling, allocate loop, thread leak)
  /\b(?:thread(?:[-\s]?leak)|handle(?:[-\s]?leak)|descriptor(?:[-\s]?leak)|socket(?:[-\s]?leak)|allocation(?:[-\s]?storm)|memory(?:[-\s]?blast|[-\s]?storm))\b/i,

  // other DoS-related primitives (heap spray is often used for exploitation but can show resource abuse)
  /\b(?:heap(?:[-\s]?spray)|allocation(?:[-\s]?bomb))\b/i,
];

// Enhanced client-side signal detection (low false-positive)
const clientSignalPatterns: RegExp[] = [
  // client-side / client side / clientside (allow hyphen, space, or none)
  /\bclient(?:[-\s]?side|side)\b/i,
  /\bclientside\b/i, // explicit no-hyphen form if text is normalized

  // Browsers and rendering engines (include common engine tokens)
  /\b(?:browser|web browser|chrome|google chrome|chromium|firefox|mozilla firefox|edge|msedge|safari|webkit|blink|internet explorer|ie|msie|trident|opera|opera mini|uc browser|brave)\b/i,
  /\b(?:android webview|webview|web view)\b/i,
  /\b(?:render(?:er|ing) engine|render engine|layout engine)\b/i,

  // Client application hosts / runtimes / containers (desktop, mobile, electron, office viewers)
  /\bclient(?: application| app| software| program| binary)\b/i,
  /\bdesktop (?:application|app|client)\b/i,
  /\bworkstation (?:application|app|client)\b/i,
  /\bendpoint (?:agent|client)\b/i,
  /\b(?:viewer|reader|player|media player)\b/i,
  /\bmobile\s+(?:app(?:lication)?|client|browser|device|endpoint|platform)\b/i,
  /\b(?:android\s+(?:app(?:lication)?|client|browser|device|endpoint|platform)|google\s+android)\b/i,
  /\b(?:apple\s+ios|ios[,/\s]+ipad(?:os)?|ios\s+(?:app(?:lication)?|client|device|devices|platform|version|versions|and\s+ipad(?:os)?|and\s+iphone)|ipad(?:os)?|iphone|ipod\s+touch)\b/i,
  /\btablet\s+(?:app|application|client|device)\b/i,
  /\b(?:electron|nwjs|cordova|capacitor|react[-\s]?native)\b/i,

  // Local user / user interaction / prompt / click required variants
  /\b(?:local user|local account|local privilege)\b/i,
  /\b(?:user[-\s]?interaction|required user interaction|user prompt|click(?: required|ing)?|confirmation required|consent required)\b/i,

  // Interaction vectors often mentioned with client impact
  /\b(?:social engineering|malicious attachment|drive[-\s]?by|drive[-\s]?by download|click[-\s]?jacking|phishing)\b/i,

  // Short tokens guarded by boundaries to avoid mid-word matches
  /(?:^|[^a-z0-9])(motw|mark of the web|zone\.identifier)(?:[^a-z0-9]|$)/i,
];

// Enhanced client application / artifact detection (low false-positive)
const clientApplicationPatterns: RegExp[] = [
  // Microsoft Office suite (Word/Excel/PowerPoint/Outlook/Visio/Project + Office 365 variants)
  /\b(?:microsoft[-\s]?office|office(?: 365)?|ms[-]?office)\b/i,
  /\b(?:microsoft[-\s]?(?:word|excel|powerpoint|outlook|project|visio|onenote|access))\b/i,
  // Office file extensions and container formats (doc, docx, xls, xlsx, ppt, pptx, rtf)
  /(?:^|[^a-z0-9])(?:\.(?:docx?|xlsx?|pptx?|rtf|msg))(?:[^a-z0-9]|$)/i,
  /\b(?:office (?:document|file|attachment))\b/i,

  // HTML/JS/ActiveX/legacy engine tokens (mshtml, mshta, jscript, vbscript, activex, ole)
  /(?:^|[^a-z0-9])(?:mshtml|mshta|msdt)(?:[^a-z0-9]|$)/i,
  /(?:^|[^a-z0-9])(?:jscript|vbscript|activex|ole|ole32|oleaut32)(?:[^a-z0-9]|$)/i,

  // SmartScreen / Mark of the Web (MOTW) / zone identifiers
  /\b(?:smart[-\s]?screen)\b/i,
  /(?:^|[^a-z0-9])(?:mark of the web|motw|zone\.identifier)(?:[^a-z0-9]|$)/i,

  // Adobe products and common PDF hints
  /\b(?:adobe(?: Reader| Acrobat| Reader DC| Acrobat DC)?|acrobat(?: DC)?)\b/i,
  /(?:^|[^a-z0-9])(?:pdf|\.pdf)(?:[^a-z0-9]|$)/i,

  // Archive / compression tools
  /\b(?:winrar|rar(?: archive)?|7[-\s]?zip|7zip|unrar|archive manager|zip(?: archive)?)\b/i,

  // Media players / Windows Media Center hints
  /\b(?:windows media(?: player| center)?|media player|wmplayer)\b/i,
  /\b(?:mp3|mp4|mkv|media(?: file| container))\b/i,

  // Fonts / font engines (truetype, opentype)
  /\b(?:truetype|opentype|ttf|otf|font(?: parsing| engine| library)?)\b/i,

  // Browser / UI host tokens often used as client vectors
  /\b(?:internet explorer|iexplore|edge|msedge|browser helper object|bho)\b/i,

  // Generic document container / compound formats (OLE compound, compound file binary format)
  /\b(?:ole(?:\s+compound)?|compound file|cfb|com)\b/i,
];

const clientFileInteractionPatterns: RegExp[] = [
  // malicious file indicators with bounded context
  /\bmalicious[\s\S]{0,120}?\b(?:document|file|attachment|email|message|image|font|media|archive|spreadsheet|presentation|installer|package)\b/i,
  /\b(?:specially|specifically)\s+crafted\s+(?:document|file|attachment|email|message|image|font|media|archive|spreadsheet|presentation|installer|package)\b/i,

  // verbs that indicate opening/processing/parsing a file or content (limited context window)
  /\b(?:open(?:ing)?|view(?:ing)?|preview(?:ing)?|load(?:ing)?|render(?:ing)?)'?\b[\s\S]{0,120}?\b(?:document|file|attachment|email|message|image|font|media|archive|content|payload)\b/i,

  // delivered via/through/by email
  /(?:^|[^a-z0-9])(?:delivered (?:via|through|by) (?:email|attachment|msg|eml))(?:[^a-z0-9]|$)/i,

  // "when viewing/opening/loading" followed by many common launcher/document extensions
  /\bwhen (?:viewing|opening|loading)[\s\S]{0,80}?\.(?:docx?|rtf|xlsx?|xls|pptx?|ppt|pdf|eml|msg|zip|rar|iso|lnk|rdp|chm|url|website|msc|hta|scf|ps1|vbs|js|jar)(?:\b|$)/i,

  // explicit "click to run / double-click / open the .lnk" type phrasing (short context window)
  /\b(?:click(?: to)? (?:open|run|execute|to run)|double[-\s]?click|right[-\s]?click)[\s\S]{0,40}?\.(?:lnk|rdp|chm|url|exe|ps1|vbs|hta|scf)(?:\b|$)/i,

  // attachment names or received as an attachment indicator
  /\b(?:attached (?:file|attachment)|attachment:|attachment name|received as an attachment)\b/i,
];

const clientUserInteractionPatterns: RegExp[] = [
  // explicit attachment references (guarded)
  /\b(?:email attachment|attached file|malicious attachment)\b/i,

  // phishing / social engineering phrases
  /\bphishing(?: (?:email|message|campaign))?\b/i,
  /\bsocial[-\s]?engineering\b/i,

  // required user actions (open/click/interact/confirm)
  /\b(?:requires? (?:user )?interaction|user must (?:open|click|interact|confirm)|click (?:to|here)|user[-\s]?prompt|confirmation required)\b/i,

  // "drive-by", "click-to-exploit" style phrases
  /\b(?:drive[-\s]?by|drive[-\s]?by download|click[-\s]?to[-\s]?open|click[-\s]?jacking)\b/i,
];

const clientLocalExecutionPatterns: RegExp[] = [
  // local attacker / locally authenticated / local user
  /\b(?:local(?:ly)? (?:attacker|user|account)|locally authenticated|local account|local access)\b/i,

  // local privilege escalation or local execution phrases
  /\b(?:local[-\s]?privilege(?:[-\s]?escalation| escalation)|LPE|privilege escalation(?: via)?)\b/i,
  /\b(?:execute(?:s|d)? arbitrary code locally|execute (?:arbitrary|remote)? code in (?:user|kernel) mode|run arbitrary code locally)\b/i,
];

const explicitFileUserActionPatterns: RegExp[] = [
  /\b(?:when|upon)\s+(?:opening|viewing|loading|double[-\s]?clicking|launching)\b/i,
  /\b(?:user|victim|target)\s+(?:opens|open|opening|views|downloads|executes|runs|launches)\b/i,
  /\bdouble[-\s]?click(?:ing)?\b/i,
  /\bclicks?\s+(?:on|to)\b/i,
];

const serverFileContextPatterns: RegExp[] = [
  /\bupload(?:ed|ing)?\b/i,
  /\b(?:http|https|api)\s+(?:request|call|endpoint)\b/i,
  /\bserver\s+(?:processes|parses|handles)\b/i,
  /\bvia\s+(?:an?\s+)?(?:api|http)\s+request\b/i,
];

const networkProtocolPatterns: RegExp[] = [
  /\b(?:smb|smbv1|smbv2|smbv3|cifs|nfs|rpc|msrpc|rdp|rdweb|ldap|ldaps|ftp|sftp|smtp|imap|pop3|snmp|telnet|ssh|dcerpc|dce\/?rpc|tcp|udp|nntp|mapi)\b/i,
];

const kernelServerPatterns: RegExp[] = [
  /\b(?:kernel(?:[-\s]?mode)?|kernel[-\s]?space|kernel driver|system driver|device driver|ntoskrnl|win32k)\b/i,
];

const serverSignalPatterns: RegExp[] = [
  ...networkProtocolPatterns,
  // management / admin interfaces
  /\b(?:web[-\s]?based management|management (?:server|interface|console)|admin(?:istration)? (?:interface|console|portal))\b/i,

  // network / remote service signals
  /\b(?:remote service|http service|https service|network service|tcp service|listens on port|listening on port)\b/i,

  // gateway, vpn, firewall, router, switch
  /\b(?:gateway|vpn|firewall|router|switch|load[-\s]?balancer)\b/i,

  // server-side file inclusion keywords (LFI)
  /\b(?:local file inclusion|lfi|file inclusion)\b/i,

  // API / REST / SOAP / RPC / management endpoints
  /\b(?:api endpoint|rest(?: API)?|soap|rpc|management endpoint|control plane)\b/i,
];

const genericServerTokenPattern = /\b(?:server|service|daemon|appliance|controller)\b/i;
const clientDomainHints: ReadonlySet<KevDomainCategory> = new Set(["Browsers"]);

const serverDomainHints: ReadonlySet<KevDomainCategory> = new Set([
  "Web Applications",
  "Web Servers",
  "Mail Servers",
  "Networking & VPN",
  "Industrial Control Systems",
  "Cloud & SaaS",
  "Virtualization & Containers",
  "Database & Storage",
  "Security Appliances",
]);

const rcePatterns: RegExp[] = [
  ...remoteExecutionPatterns,
  ...codeExecutionPatterns,
];

const vulnerabilityRules: Array<{
  category: KevVulnerabilityCategory;
  patterns: RegExp[];
}> = [
  {
    category: "Command Injection",
    patterns: [/(command injection|os command|system\(|shell command)/i],
  },
  {
    category: "SQL Injection",
    patterns: [/(sql injection|blind sql|sqli)/i],
  },
  {
    category: "Cross-Site Scripting",
    patterns: [/(cross-site scripting|xss)/i],
  },
  {
    category: "Server-Side Request Forgery",
    patterns: [/(server-side request forgery|ssrf)/i],
  },
  {
    category: "Directory Traversal",
    patterns: [/(directory traversal|path traversal|dot-dot)/i],
  },
  {
    category: "Memory Corruption",
    patterns: memoryCorruptionPatterns,
  },
  {
    category: "Remote Code Execution",
    patterns: rcePatterns,
  },
  {
    category: "Authentication Bypass",
    patterns: [
      /(authentication bypass|bypass authentication|unauthenticated access|without authentication|authorization bypass)/i,
    ],
  },
  {
    category: "Information Disclosure",
    patterns: [
      /(information disclosure|data leak|information leak|exposure|sensitive information)/i,
    ],
  },
  {
    category: "Denial of Service",
    patterns: [
      /(denial of service|dos attack|service disruption|resource exhaustion|crash)/i,
    ],
  },
  {
    category: "Logic Flaw",
    patterns: [
      /(logic flaw|business logic|improper validation|improper access control)/i,
    ],
  },
];

const normalise = (value: string) => value.toLowerCase();

const matchCategory = <T extends string>(
  text: string,
  rules: Array<{ category: T; patterns: RegExp[] }>,
  fallback: T
): T[] => {
  const found = new Set<T>();

  for (const rule of rules) {
    if (rule.patterns.some((pattern) => pattern.test(text))) {
      found.add(rule.category);
    }
  }

  if (!found.size) {
    found.add(fallback);
  }

  return Array.from(found);
};

export const classifyDomainCategories = (
  entry: Pick<
    KevBaseEntry,
    "vendor" | "product" | "vulnerabilityName" | "description" | "cvssVector"
  >
): { categories: KevDomainCategory[]; internetExposed: boolean } => {
  const source = normalise(`${entry.vendor} ${entry.product}`);
  const context = normalise(
    `${entry.vulnerabilityName ?? ""} ${entry.description ?? ""}`
  );
  const text = `${source} ${context}`;
  const categories = new Set(matchCategory(text, domainRules, "Other"));

  const isBrowser =
    categories.has("Browsers") || matchesAny(source, webNegativePatterns);
  const isWebServer =
    categories.has("Web Servers") || matchesAny(source, webServerPatterns);
  const isWebProduct = matchesAny(source, webProductPatterns);
  const isWebDevice = matchesAny(source, webDevicePatterns);
  const hasWebIndicators = matchesAny(context, webIndicatorPatterns);
  const hasStrongWebSignal = matchesAny(context, webStrongContextPatterns);
  const deviceHasWebSignal =
    isWebDevice && matchesAny(context, webDeviceContextPatterns);
  const hasManagementSignal = matchesAny(context, webManagementPatterns);
  const hasApiSignal = matchesAny(context, webApiPatterns);
  const hasNonWebProductSignal =
    matchesAny(source, nonWebProductPatterns) ||
    matchesAny(context, nonWebProductPatterns);
  const hasNonWebContextSignal = matchesAny(context, nonWebContextPatterns);
  const isMailServer = categories.has("Mail Servers");
  const isNetworkDevice = categories.has("Networking & VPN");
  const edgeStrongProduct = matchesAny(source, edgeStrongProductPatterns);
  const edgeSupportingProduct = matchesAny(
    source,
    edgeSupportingProductPatterns
  );
  const edgeContextSignal =
    matchesAny(context, edgeContextPatterns) ||
    hasStrongWebSignal ||
    hasManagementSignal ||
    hasApiSignal ||
    deviceHasWebSignal;
  const edgePortalSignal = matchesAny(context, edgePortalPatterns);
  const edgeMailSignal = matchesAny(context, edgeMailPatterns);
  const remoteContextSignal = matchesAny(context, remoteContextPatterns);
  const remoteExecutionSignal =
    matchesAny(context, remoteExecutionPatterns) ||
    matchesAny(context, codeExecutionPatterns);
  const cvssTraits = parseCvssVector(entry.cvssVector);
  const networkAttackVector = cvssTraits?.attackVector === "N";
  const lowPrivileges =
    !cvssTraits?.privilegesRequired || cvssTraits.privilegesRequired === "N";
  const noUserInteraction =
    !cvssTraits?.userInteraction || cvssTraits.userInteraction === "N";

  const hasStandaloneWebIndicator =
    hasWebIndicators && !hasNonWebProductSignal && !hasNonWebContextSignal;
  const hasCombinedWebIndicator =
    hasStandaloneWebIndicator ||
    (hasWebIndicators &&
      (hasStrongWebSignal ||
        hasManagementSignal ||
        hasApiSignal ||
        isWebProduct ||
        isWebDevice ||
        isMailServer ||
        isNetworkDevice));

  const baseWebSignals =
    isWebProduct ||
    hasStrongWebSignal ||
    hasManagementSignal ||
    hasApiSignal ||
    deviceHasWebSignal ||
    (hasWebIndicators &&
      (isWebProduct ||
        isWebDevice ||
        isMailServer ||
        isNetworkDevice ||
        hasManagementSignal ||
        hasApiSignal));

  const shouldTagWeb =
    (!isBrowser && !isWebServer && baseWebSignals) || hasCombinedWebIndicator;

  const shouldPreferNonWeb =
    hasNonWebProductSignal ||
    (hasNonWebContextSignal &&
      !hasStrongWebSignal &&
      !hasManagementSignal &&
      !hasApiSignal &&
      !isWebProduct &&
      !deviceHasWebSignal &&
      !hasCombinedWebIndicator);

  const productLooksLikeServer = matchesAny(source, webServerPatterns);

  if (
    categories.has("Web Applications") &&
    categories.has("Web Servers") &&
    !productLooksLikeServer
  ) {
    categories.delete("Web Servers");
  }

  if (shouldPreferNonWeb) {
    categories.delete("Web Applications");
    categories.add("Non-Web Applications");
  } else if (shouldTagWeb) {
    categories.add("Web Applications");
  }

  if (categories.has("Web Applications")) {
    categories.delete("Non-Web Applications");
  } else if (categories.has("Web Servers") && !shouldPreferNonWeb) {
    categories.delete("Non-Web Applications");
  } else if (!shouldPreferNonWeb) {
    categories.add("Non-Web Applications");
  }

  if (categories.size > 1 && categories.has("Other")) {
    categories.delete("Other");
  }

  const domainEdgeSignal = internetEdgeDomainHints.some((category) =>
    categories.has(category)
  );
  const productConfidence =
    (edgeStrongProduct ? 2 : 0) +
    (edgeSupportingProduct ? 1 : 0) +
    (domainEdgeSignal ? 1 : 0);
  const contextConfidence =
    (edgeContextSignal ? 1.5 : 0) +
    (edgePortalSignal ? 1 : 0) +
    (edgeMailSignal ? 1 : 0);
  const remoteConfidence =
    (networkAttackVector ? 1 : 0) +
    (remoteContextSignal ? 1 : 0) +
    (remoteExecutionSignal ? 0.5 : 0) +
    (lowPrivileges ? 0.5 : 0) +
    (noUserInteraction ? 0.5 : 0);

  const hasExposureContext =
    edgeContextSignal ||
    edgePortalSignal ||
    edgeMailSignal ||
    remoteContextSignal ||
    networkAttackVector;
  const strongProductBackers =
    edgeStrongProduct ||
    (edgeSupportingProduct && hasExposureContext) ||
    domainEdgeSignal;

  const internetExposed =
    strongProductBackers &&
    hasExposureContext &&
    productConfidence + contextConfidence + remoteConfidence >= 3.5;

  if (internetExposed) {
    categories.add("Internet Edge");
  }

  return { categories: Array.from(categories), internetExposed };
};

export const classifyExploitLayers = (
  entry: {
    vulnerabilityName: string;
    description: string;
    cvssVector?: string | null;
  },
  domainCategories: KevDomainCategory[]
): KevExploitLayer[] => {
  const text = normalise(`${entry.vulnerabilityName} ${entry.description}`);
  const layers = new Set<KevExploitLayer>();

  const cvssTraits = parseCvssVector(entry.cvssVector);
  const cvssSuggestsLocal =
    cvssTraits?.attackVector === "L" || cvssTraits?.attackVector === "P";
  const cvssSuggestsRemote =
    cvssTraits?.attackVector === "N" || cvssTraits?.attackVector === "A";
  const cvssRequiresUserInteraction = cvssTraits?.userInteraction === "R";
  const cvssPreAuth = cvssTraits?.privilegesRequired === "N";

  const hasPrivilegeSignal = privilegePatterns.some((pattern) =>
    pattern.test(text)
  );

  if (hasPrivilegeSignal) {
    layers.add("Privilege Escalation");
  }

  const hasExplicitRemoteRce = matchesAny(text, remoteExecutionPatterns);
  const hasCodeExecutionSignal = matchesAny(text, codeExecutionPatterns);
  const hasRemoteContext =
    hasExplicitRemoteRce ||
    matchesAny(text, remoteContextPatterns) ||
    Boolean(cvssSuggestsRemote);

  const qualifiesForRce =
    hasExplicitRemoteRce || (hasCodeExecutionSignal && hasRemoteContext);

  const hasMemoryCorruption = memoryCorruptionPatterns.some((pattern) =>
    pattern.test(text)
  );
  const hasDosSignal = matchesAny(text, denialOfServicePatterns);
  let hasClientSignal = matchesAny(text, clientSignalPatterns);
  let hasClientApplicationSignal = matchesAny(
    text,
    clientApplicationPatterns
  );
  let hasClientFileSignal = matchesAny(text, clientFileInteractionPatterns);
  const rawClientUserInteractionSignal = matchesAny(
    text,
    clientUserInteractionPatterns
  );
  const hasExplicitFileUserAction = matchesAny(
    text,
    explicitFileUserActionPatterns
  );
  let hasClientUserInteractionSignal =
    rawClientUserInteractionSignal ||
    Boolean(cvssRequiresUserInteraction) ||
    hasExplicitFileUserAction;
  const hasServerFileProcessingContext = matchesAny(
    text,
    serverFileContextPatterns
  );
  if (hasClientFileSignal) {
    const hasTextualUserAction =
      hasExplicitFileUserAction || rawClientUserInteractionSignal;
    if (!hasTextualUserAction || (hasServerFileProcessingContext && !hasExplicitFileUserAction)) {
      hasClientFileSignal = false;
    }
  }
  const hasClientLocalExecutionSignal =
    matchesAny(text, clientLocalExecutionPatterns) ||
    Boolean(cvssSuggestsLocal);
  const hasStrongServerProtocol = matchesAny(text, networkProtocolPatterns);
  let hasServerSignal = serverSignalPatterns.some((pattern) =>
    pattern.test(text)
  );
  const hasKernelDriverSignal = matchesAny(text, kernelServerPatterns);
  const hasKernelServerSignal =
    hasKernelDriverSignal &&
    (hasStrongServerProtocol || hasRemoteContext || hasExplicitRemoteRce);

  const networkOperatingSystemSignal = /\bcisco(?:'s)?\s+ios(?:\s+(?:xe|xr))?\b/i.test(
    text
  ) || /\bios\s+(?:xe|xr)\b/i.test(text);
  const mobileManagementSignal =
    /\b(?:mobileiron|endpoint manager mobile|ivanti (?:epmm|endpoint manager mobile)|mobileiron (?:core|sentry))\b/i.test(
      text
    );
  const mobileDeviceManagementContext = /\bmobile device management\b/i.test(
    text
  );

  if (mobileManagementSignal || mobileDeviceManagementContext) {
    hasServerSignal = true;
  }

  if (networkOperatingSystemSignal) {
    hasServerSignal = true;
  }

  const domainSuggestsClient = domainCategories.some((category) =>
    clientDomainHints.has(category)
  );
  const domainSuggestsServer = domainCategories.some((category) =>
    serverDomainHints.has(category)
  );

  if (hasClientApplicationSignal) {
    const hasClientArtifactContext =
      hasClientFileSignal ||
      hasClientUserInteractionSignal ||
      hasExplicitFileUserAction ||
      domainSuggestsClient;
    const serverDominantContext =
      domainSuggestsServer ||
      hasStrongServerProtocol ||
      networkOperatingSystemSignal ||
      mobileManagementSignal ||
      mobileDeviceManagementContext ||
      hasRemoteContext;

    if (!hasClientArtifactContext && serverDominantContext) {
      hasClientApplicationSignal = false;
    }
  }

  const hasGenericServerToken = genericServerTokenPattern.test(text);
  const hostileServerContext =
    /\b(?:malicious|attacker(?:-controlled)?|adversary|rogue|fake)\s+(?:server|service|daemon|appliance|controller)s?\b/i.test(
      text
    );

  if (
    hasGenericServerToken &&
    (!hostileServerContext ||
      domainSuggestsServer ||
      hasStrongServerProtocol ||
      networkOperatingSystemSignal ||
      mobileManagementSignal ||
      mobileDeviceManagementContext ||
      hasRemoteContext)
  ) {
    hasServerSignal = true;
  }

  if (
    hasClientSignal &&
    (networkOperatingSystemSignal ||
      ((mobileManagementSignal || mobileDeviceManagementContext) &&
        domainSuggestsServer &&
        !domainSuggestsClient))
  ) {
    hasClientSignal = false;
  }

  const strongClientIndicators =
    hasClientApplicationSignal ||
    hasClientFileSignal ||
    hasClientUserInteractionSignal ||
    hasClientLocalExecutionSignal ||
    domainSuggestsClient;

  const strongServerIndicators =
    hasServerSignal ||
    domainSuggestsServer ||
    hasStrongServerProtocol ||
    hasKernelServerSignal ||
    (hasRemoteContext && !strongClientIndicators);

  const clientScoreBase =
    (hasClientSignal ? 2 : 0) +
    (hasClientApplicationSignal ? 2 : 0) +
    (hasClientFileSignal ? 2 : 0) +
    (hasClientUserInteractionSignal ? 1 : 0) +
    (hasClientLocalExecutionSignal ? 1 : 0) +
    (domainSuggestsClient ? 1 : 0);

  let clientScore = clientScoreBase;

  if (clientScoreBase > 0) {
    if (cvssSuggestsLocal) {
      clientScore += 1;
    }
    if (cvssRequiresUserInteraction) {
      clientScore += 1;
    }
  }

  let serverScoreBase =
    (hasServerSignal ? 2 : 0) +
    (domainSuggestsServer ? 1 : 0) +
    (hasStrongServerProtocol ? 3 : 0) +
    (hasKernelServerSignal ? 2 : 0);

  if (hasRemoteContext && !strongClientIndicators) {
    serverScoreBase += 1;
  }

  let serverScore = serverScoreBase;

  if (serverScoreBase > 0) {
    if (cvssSuggestsRemote && !cvssRequiresUserInteraction) {
      serverScore += 1;
    }
    if (cvssPreAuth) {
      serverScore += 1;
    }
  }

  const determineSide = (): "Client-side" | "Server-side" => {
    if (clientScore > serverScore) {
      return "Client-side";
    }

    if (serverScore > clientScore) {
      return "Server-side";
    }

    if (strongServerIndicators && !strongClientIndicators) {
      return "Server-side";
    }

    if (domainSuggestsServer && !domainSuggestsClient) {
      return "Server-side";
    }

    if (hasServerSignal && !hasClientSignal) {
      return "Server-side";
    }

    if (strongClientIndicators && !strongServerIndicators) {
      return "Client-side";
    }

    if (domainSuggestsClient && !domainSuggestsServer) {
      return "Client-side";
    }

    if (hasClientSignal && !hasServerSignal) {
      return "Client-side";
    }

    if (strongServerIndicators) {
      return "Server-side";
    }

    if (strongClientIndicators) {
      return "Client-side";
    }

    if (hasServerSignal) {
      return "Server-side";
    }

    if (hasClientSignal) {
      return "Client-side";
    }

    return hasRemoteContext ? "Server-side" : "Client-side";
  };

  if (!qualifiesForRce) {
    if (hasDosSignal) {
      const dosSide = determineSide();
      layers.add(
        dosSide === "Client-side" ? "DoS · Client-side" : "DoS · Server-side"
      );
    }
    return Array.from(layers);
  }

  const side = determineSide();

  const labelMap: Record<
    "Client-side" | "Server-side",
    { memory: KevExploitLayer; nonMemory: KevExploitLayer }
  > = {
    "Client-side": {
      memory: "RCE · Client-side Memory Corruption",
      nonMemory: "RCE · Client-side Non-memory",
    },
    "Server-side": {
      memory: "RCE · Server-side Memory Corruption",
      nonMemory: "RCE · Server-side Non-memory",
    },
  };

  const label = hasMemoryCorruption
    ? labelMap[side].memory
    : labelMap[side].nonMemory;

  layers.add(label);

  if (hasDosSignal) {
    layers.add(
      side === "Client-side" ? "DoS · Client-side" : "DoS · Server-side"
    );
  }

  return Array.from(layers);
};

export const classifyVulnerabilityCategories = (entry: {
  vulnerabilityName: string;
  description: string;
}): KevVulnerabilityCategory[] => {
  const text = normalise(`${entry.vulnerabilityName} ${entry.description}`);
  const categories = matchCategory(text, vulnerabilityRules, "Other");

  return categories;
};

export const enrichEntry = (entry: KevBaseEntry): KevEntry => {
  const { categories: domainCategories, internetExposed } =
    classifyDomainCategories(entry);
  const exploitLayers = classifyExploitLayers(entry, domainCategories);
  const vulnerabilityCategories = classifyVulnerabilityCategories(entry);

  return {
    ...entry,
    domainCategories,
    exploitLayers,
    vulnerabilityCategories,
    internetExposed,
  };
};

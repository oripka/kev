export interface VendorProductOverride {
  pattern: RegExp
  vendor: string
  product: string
  notes?: string
}

export const vendorProductOverrides: VendorProductOverride[] = [
  {
    pattern: /igel os use of a key past its expiration date vulnerability/i,
    vendor: 'IGEL',
    product: 'IGEL OS'
  },
  {
    pattern: /appsmith rce/i,
    vendor: 'Appsmith',
    product: 'Appsmith'
  },
  {
    pattern: /vmware esxi arbitrary write vulnerability/i,
    vendor: 'VMware',
    product: 'ESXi'
  },
  {
    pattern: /vmware esxi,? workstation,? and fusion information disclosure/i,
    vendor: 'VMware',
    product: 'ESXi / Workstation / Fusion'
  },
  {
    pattern: /netis router exploit chain reactor/i,
    vendor: 'Netis',
    product: 'Netis Routers'
  },
  {
    pattern: /beyondtrust privileged remote access.*remote support/i,
    vendor: 'BeyondTrust',
    product: 'Privileged Remote Access / Remote Support'
  },
  {
    pattern: /cleo multiple products (?:unauthenticated|unrestricted) file upload/i,
    vendor: 'Cleo',
    product: 'Harmony / VLTrader / LexiCom'
  },
  {
    pattern: /pyload rce/i,
    vendor: 'pyLoad',
    product: 'pyLoad'
  },
  {
    pattern: /cyberpanel incorrect default permissions vulnerability/i,
    vendor: 'CyberPanel',
    product: 'CyberPanel'
  },
  {
    pattern: /synacor zimbra collaboration suite/i,
    vendor: 'Synacor',
    product: 'Zimbra Collaboration Suite'
  },
  {
    pattern: /vmware vcenter server privilege escalation/i,
    vendor: 'VMware',
    product: 'vCenter Server'
  },
  {
    pattern: /vmware vcenter server heap-based buffer overflow/i,
    vendor: 'VMware',
    product: 'vCenter Server'
  },
  {
    pattern: /mitel sip phones argument injection/i,
    vendor: 'Mitel',
    product: '6800/6900 Series SIP Phones'
  },
  {
    pattern: /twilio authy information disclosure/i,
    vendor: 'Twilio',
    product: 'Authy'
  },
  {
    pattern: /vcenter sudo privilege escalation/i,
    vendor: 'VMware',
    product: 'vCenter Server'
  },
  {
    pattern: /ghostscript command execution via format string/i,
    vendor: 'Artifex Software',
    product: 'Ghostscript'
  },
  {
    pattern: /netis router mw5360/i,
    vendor: 'Netis',
    product: 'MW5360 Router'
  },
  {
    pattern: /array networks ag.*arrayos missing authentication/i,
    vendor: 'Array Networks',
    product: 'ArrayOS'
  },
  {
    pattern: /d-link dnr-322l download of code without integrity check/i,
    vendor: 'D-Link',
    product: 'DNR-322L'
  },
  {
    pattern: /dante discovery process control/i,
    vendor: 'Audinate',
    product: 'Dante Discovery'
  },
  {
    pattern: /microsoft windows remote code execution/i,
    vendor: 'Microsoft',
    product: 'Windows'
  },
  {
    pattern: /microsoft office excel remote code execution/i,
    vendor: 'Microsoft',
    product: 'Office Excel'
  },
  {
    pattern: /nuuo nvrmini2 devices missing authentication/i,
    vendor: 'NUUO',
    product: 'NVRmini2'
  },
  {
    pattern: /usaherds use of hard-coded credentials/i,
    vendor: 'Acclaim Systems',
    product: 'USAHERDS'
  },
  {
    pattern: /dahua ip camera authentication bypass/i,
    vendor: 'Dahua',
    product: 'IP Camera'
  },
  {
    pattern: /d-link dcs-2530l and dcs-2670l devices unspecified/i,
    vendor: 'D-Link',
    product: 'DCS-2530L / DCS-2670L'
  },
  {
    pattern: /sophos xg firewall buffer overflow/i,
    vendor: 'Sophos',
    product: 'XG Firewall'
  },
  {
    pattern: /multi-router looking glass.*buffer overflow/i,
    vendor: 'Multi-Router Looking Glass',
    product: 'MRLG'
  },
  {
    pattern: /juniper screenos improper authentication/i,
    vendor: 'Juniper Networks',
    product: 'ScreenOS'
  },
  {
    pattern: /timbuktu plughntcommand named pipe buffer overflow/i,
    vendor: 'Timbuktu',
    product: 'Timbuktu Pro'
  },
  {
    pattern: /cyrus imapd pop3d popsubfolders user buffer overflow/i,
    vendor: 'Cyrus IMAP',
    product: 'IMAPD'
  }
]

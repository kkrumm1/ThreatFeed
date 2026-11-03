function FindProxyForURL(url, host) {
	// NBISD TEST PAC for 316060 only (Copy of iOS) - force Google sign-in through iboss - 11/03/26
	var P = "PROXY cn-809088930-32-8vnsg14778.ibosscloud.com:9595; PROXY cn-1793906582-19-vnsg15071.ibosscloud.com:9595; PROXY cn-809088742-9-vnsg15026.ibosscloud.com:9595";
	var ip = dnsResolve(host);

	// Force Google sign-in through iboss (tenant restriction test)
	if (shExpMatch(host, "accounts.google.com") || shExpMatch(host, "*.accounts.google.com")) { return P; }

	// iboss
	if (shExpMatch(host, "iboss.com") || shExpMatch(host, "*.iboss.com") || shExpMatch(host, "ibosscloud.com") || shExpMatch(host, "*.ibosscloud.com")) { return "DIRECT"; }

	// Local / private
	if (isPlainHostName(host) || shExpMatch(host, "*.local") || host === "localhost") { return "DIRECT"; }
	if (ip && (isInNet(ip, "10.0.0.0", "255.0.0.0") || isInNet(ip, "172.16.0.0", "255.240.0.0") || isInNet(ip, "192.168.0.0", "255.255.0.0") || isInNet(ip, "127.0.0.0", "255.0.0.0") || isInNet(ip, "169.254.0.0", "255.255.0.0"))) { return "DIRECT"; }

	// Apple (MDM, updates, iCloud, App Store)
	if ((ip && isInNet(ip, "17.0.0.0", "255.0.0.0")) ||
		shExpMatch(host, "apple.com") || shExpMatch(host, "*.apple.com") ||
		shExpMatch(host, "icloud.com") || shExpMatch(host, "*.icloud.com") ||
		shExpMatch(host, "icloud-content.com") || shExpMatch(host, "*.icloud-content.com") ||
		shExpMatch(host, "mzstatic.com") || shExpMatch(host, "*.mzstatic.com") ||
		shExpMatch(host, "cdn-apple.com") || shExpMatch(host, "*.cdn-apple.com") ||
		shExpMatch(host, "apple-cloudkit.com") || shExpMatch(host, "*.apple-cloudkit.com") ||
		shExpMatch(host, "itunes.com") || shExpMatch(host, "*.itunes.com")) { return "DIRECT"; }

	// Jamf
	if (dnsDomainIs(host, ".jamf.com") || dnsDomainIs(host, ".jamfcloud.com") || dnsDomainIs(host, ".jamf.io") || dnsDomainIs(host, ".jamf.one") || dnsDomainIs(host, ".wandera.com")) { return "DIRECT"; }

	// nbisd
	if (shExpMatch(host, "*.nbisd.edu") || shExpMatch(host, "nbisd.edu") || shExpMatch(host, "clearpass.nbisd.org")) { return "DIRECT"; }

	return P;
}

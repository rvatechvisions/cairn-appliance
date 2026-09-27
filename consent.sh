# Which consent capability each preflight step needs. Sourced by preflight.sh
# and by consent-map-test.sh; never run on its own.
#
# **CONFIRMED** in the rulings on the v4.85 checkpoint (WO-0927-M, R4), as read
# here: determined from what each step calls, not from its name. A step added
# later with no mapping fails consent-map-test.sh and is refused at run time;
# it never defaults to permitted.
#
# Consent is granted per capability and enforced per step. A step that maps to
# nothing is REFUSED, never run: an unmapped step would be a way to keep
# reading something a client turned off.
#
#   step              what it calls                                      needs
#   kerberos          kinit with the directory credential; reads no      (prerequisite)
#                     directory data
#   ldap              ldapsearch, base object of the domain naming       ad
#                     context, attribute dnsHostName
#   dns-zones         ldapsearch under CN=MicrosoftDNS,DC=DomainDnsZones  ad
#   dhcp-authorized   ldapsearch under CN=NetServices,CN=Services,       ad
#                     CN=Configuration for dHCPClass / dhcpServers --
#                     an Active Directory read, whatever the name says
#   dhcp              the preflight binary: MS-DHCPM R_DhcpEnumSubnets   dhcp
#                     and R_DhcpEnumSubnetClientsV5 against the servers
#                     named in the settings file, not ones read from AD
#
# kerberos is the one step that spans capabilities: every other step
# authenticates through the ticket it obtains. It reads nothing itself, so it
# runs when ANY capability is granted and not otherwise. That is stated here
# rather than decided silently, and it is part of what a person confirms.

# The capability a step needs, or PREREQUISITE, or UNMAPPED.
step_capability() {
  case "$1" in
    kerberos) printf 'PREREQUISITE\n' ;;
    ldap|dns-zones|dhcp-authorized) printf 'ad\n' ;;
    dhcp) printf 'dhcp\n' ;;
    *) printf 'UNMAPPED\n' ;;
  esac
}

# Whether the comma-separated list in $2 permits the step named in $1.
# An empty list permits nothing, including the prerequisite.
step_permitted() {
  local step="$1" granted="$2" needs
  needs="$(step_capability "$step")"

  case "$needs" in
    UNMAPPED) return 1 ;;
    PREREQUISITE) [ -n "$granted" ] ;;
    *)
      case ",${granted}," in
        *",${needs},"*) return 0 ;;
        *) return 1 ;;
      esac
      ;;
  esac
}

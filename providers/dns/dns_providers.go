package dns

import (
	"fmt"

	"github.com/adi658/cert-manager/challenge"
	"github.com/adi658/cert-manager/challenge/dns01"
	"github.com/adi658/cert-manager/providers/dns/acmedns"
	"github.com/adi658/cert-manager/providers/dns/alidns"
	"github.com/adi658/cert-manager/providers/dns/auroradns"
	"github.com/adi658/cert-manager/providers/dns/azure"
	"github.com/adi658/cert-manager/providers/dns/bindman"
	"github.com/adi658/cert-manager/providers/dns/bluecat"
	"github.com/adi658/cert-manager/providers/dns/cloudflare"
	"github.com/adi658/cert-manager/providers/dns/cloudns"
	"github.com/adi658/cert-manager/providers/dns/cloudxns"
	"github.com/adi658/cert-manager/providers/dns/conoha"
	"github.com/adi658/cert-manager/providers/dns/designate"
	"github.com/adi658/cert-manager/providers/dns/digitalocean"
	"github.com/adi658/cert-manager/providers/dns/dnsimple"
	"github.com/adi658/cert-manager/providers/dns/dnsmadeeasy"
	"github.com/adi658/cert-manager/providers/dns/dnspod"
	"github.com/adi658/cert-manager/providers/dns/dode"
	"github.com/adi658/cert-manager/providers/dns/dreamhost"
	"github.com/adi658/cert-manager/providers/dns/duckdns"
	"github.com/adi658/cert-manager/providers/dns/dyn"
	"github.com/adi658/cert-manager/providers/dns/easydns"
	"github.com/adi658/cert-manager/providers/dns/exec"
	"github.com/adi658/cert-manager/providers/dns/exoscale"
	"github.com/adi658/cert-manager/providers/dns/fastdns"
	"github.com/adi658/cert-manager/providers/dns/gandi"
	"github.com/adi658/cert-manager/providers/dns/gandiv5"
	"github.com/adi658/cert-manager/providers/dns/gcloud"
	"github.com/adi658/cert-manager/providers/dns/glesys"
	"github.com/adi658/cert-manager/providers/dns/godaddy"
	"github.com/adi658/cert-manager/providers/dns/hostingde"
	"github.com/adi658/cert-manager/providers/dns/httpreq"
	"github.com/adi658/cert-manager/providers/dns/iij"
	"github.com/adi658/cert-manager/providers/dns/inwx"
	"github.com/adi658/cert-manager/providers/dns/joker"
	"github.com/adi658/cert-manager/providers/dns/lightsail"
	"github.com/adi658/cert-manager/providers/dns/linode"
	"github.com/adi658/cert-manager/providers/dns/linodev4"
	"github.com/adi658/cert-manager/providers/dns/mydnsjp"
	"github.com/adi658/cert-manager/providers/dns/namecheap"
	"github.com/adi658/cert-manager/providers/dns/namedotcom"
	"github.com/adi658/cert-manager/providers/dns/netcup"
	"github.com/adi658/cert-manager/providers/dns/nifcloud"
	"github.com/adi658/cert-manager/providers/dns/ns1"
	"github.com/adi658/cert-manager/providers/dns/oraclecloud"
	"github.com/adi658/cert-manager/providers/dns/otc"
	"github.com/adi658/cert-manager/providers/dns/ovh"
	"github.com/adi658/cert-manager/providers/dns/pdns"
	"github.com/adi658/cert-manager/providers/dns/rackspace"
	"github.com/adi658/cert-manager/providers/dns/rfc2136"
	"github.com/adi658/cert-manager/providers/dns/route53"
	"github.com/adi658/cert-manager/providers/dns/sakuracloud"
	"github.com/adi658/cert-manager/providers/dns/selectel"
	"github.com/adi658/cert-manager/providers/dns/stackpath"
	"github.com/adi658/cert-manager/providers/dns/transip"
	"github.com/adi658/cert-manager/providers/dns/vegadns"
	"github.com/adi658/cert-manager/providers/dns/versio"
	"github.com/adi658/cert-manager/providers/dns/vscale"
	"github.com/adi658/cert-manager/providers/dns/vultr"
	"github.com/adi658/cert-manager/providers/dns/zoneee"
)

// NewDNSChallengeProviderByName Factory for DNS providers
func NewDNSChallengeProviderByName(name string) (challenge.Provider, error) {
	switch name {
	case "acme-dns":
		return acmedns.NewDNSProvider()
	case "alidns":
		return alidns.NewDNSProvider()
	case "azure":
		return azure.NewDNSProvider()
	case "auroradns":
		return auroradns.NewDNSProvider()
	case "bindman":
		return bindman.NewDNSProvider()
	case "bluecat":
		return bluecat.NewDNSProvider()
	case "cloudflare":
		return cloudflare.NewDNSProvider()
	case "cloudns":
		return cloudns.NewDNSProvider()
	case "cloudxns":
		return cloudxns.NewDNSProvider()
	case "conoha":
		return conoha.NewDNSProvider()
	case "designate":
		return designate.NewDNSProvider()
	case "digitalocean":
		return digitalocean.NewDNSProvider()
	case "dnsimple":
		return dnsimple.NewDNSProvider()
	case "dnsmadeeasy":
		return dnsmadeeasy.NewDNSProvider()
	case "dnspod":
		return dnspod.NewDNSProvider()
	case "dode":
		return dode.NewDNSProvider()
	case "dreamhost":
		return dreamhost.NewDNSProvider()
	case "duckdns":
		return duckdns.NewDNSProvider()
	case "dyn":
		return dyn.NewDNSProvider()
	case "fastdns":
		return fastdns.NewDNSProvider()
	case "easydns":
		return easydns.NewDNSProvider()
	case "exec":
		return exec.NewDNSProvider()
	case "exoscale":
		return exoscale.NewDNSProvider()
	case "gandi":
		return gandi.NewDNSProvider()
	case "gandiv5":
		return gandiv5.NewDNSProvider()
	case "glesys":
		return glesys.NewDNSProvider()
	case "gcloud":
		return gcloud.NewDNSProvider()
	case "godaddy":
		return godaddy.NewDNSProvider()
	case "hostingde":
		return hostingde.NewDNSProvider()
	case "httpreq":
		return httpreq.NewDNSProvider()
	case "iij":
		return iij.NewDNSProvider()
	case "inwx":
		return inwx.NewDNSProvider()
	case "joker":
		return joker.NewDNSProvider()
	case "lightsail":
		return lightsail.NewDNSProvider()
	case "linode":
		return linode.NewDNSProvider()
	case "linodev4":
		return linodev4.NewDNSProvider()
	case "manual":
		return dns01.NewDNSProviderManual()
	case "mydnsjp":
		return mydnsjp.NewDNSProvider()
	case "namecheap":
		return namecheap.NewDNSProvider()
	case "namedotcom":
		return namedotcom.NewDNSProvider()
	case "netcup":
		return netcup.NewDNSProvider()
	case "nifcloud":
		return nifcloud.NewDNSProvider()
	case "ns1":
		return ns1.NewDNSProvider()
	case "oraclecloud":
		return oraclecloud.NewDNSProvider()
	case "otc":
		return otc.NewDNSProvider()
	case "ovh":
		return ovh.NewDNSProvider()
	case "pdns":
		return pdns.NewDNSProvider()
	case "rackspace":
		return rackspace.NewDNSProvider()
	case "route53":
		return route53.NewDNSProvider()
	case "rfc2136":
		return rfc2136.NewDNSProvider()
	case "sakuracloud":
		return sakuracloud.NewDNSProvider()
	case "stackpath":
		return stackpath.NewDNSProvider()
	case "selectel":
		return selectel.NewDNSProvider()
	case "transip":
		return transip.NewDNSProvider()
	case "vegadns":
		return vegadns.NewDNSProvider()
	case "versio":
		return versio.NewDNSProvider()
	case "vultr":
		return vultr.NewDNSProvider()
	case "vscale":
		return vscale.NewDNSProvider()
	case "zoneee":
		return zoneee.NewDNSProvider()
	default:
		return nil, fmt.Errorf("unrecognized DNS provider: %s", name)
	}
}

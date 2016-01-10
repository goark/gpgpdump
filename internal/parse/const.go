package parse

// Names is name list
type Names []string

// Get returns name
func (n Names) Get(idx int) string {
	if idx < 0 || len(n) < idx {
		return "Unknown"
	}
	return n[idx]
}

// tagnames is tag name list
var tagnames = Names{
	"Reserved",
	"Public-Key Encrypted Session Key Packet",
	"Signature Packet",
	"Symmetric-Key Encrypted Session Key Packet",
	"One-Pass Signature Packet",
	"Secret-Key Packet",
	"Public-Key Packet",
	"Secret-Subkey Packet",
	"Compressed Data Packet",
	"Symmetrically Encrypted Data Packet",
	"Marker Packet",
	"Literal Data Packet",
	"Trust Packet",
	"User ID Packet",
	"Public-Subkey Packet",
	"Unknown",
	"Unknown",
	"User Attribute Packet",
	"Sym. Encrypted and Integrity Protected Data Packet",
	"Modification Detection Code Packet",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Private or Experimental Values",
	"Private or Experimental Values",
	"Private or Experimental Values",
	"Private or Experimental Values",
}

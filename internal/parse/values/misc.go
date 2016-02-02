package values

// Octets2Int returns integer from two-octets data
func Octets2Int(octets []byte) uint64 {
	rtn := uint64(0)
	if len(octets) <= 8 {
		for _, o := range octets {
			rtn = (rtn << 8) | uint64(o)
		}
	}
	return rtn
}

// Octets2IntLE returns integer from two-octets data (by little endian)
func Octets2IntLE(octets []byte) uint16 {
	rtn := uint16(0)
	if len(octets) == 2 {
		rtn = (uint16(octets[1]) << 8) | uint16(octets[0])
	}
	return rtn
}
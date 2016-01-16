package parse

import "bytes"

// PubkeyMPI - multi-precision integers of public key algorithm
type PubkeyMPI struct {
	*Options
	Pub PubAlg
	MPI []byte
}

//Parse multi-precision integers of public key algorithm
func (pm *PubkeyMPI) Parse(indent Indent) []string {
	var content = make([]string, 0)

	switch true {
	case pm.Pub.IsRSA():
		content = append(content, indent.Fill("Multi-precision integers of RSA:"))
		c := pm.mpiRSA()
		for _, l := range c {
			content = append(content, (indent + 1).Fill(l))
		}
		content = append(content, (indent + 2).Fill("-> PKCS-1"))
	case pm.Pub.IsDSA():
		content = append(content, indent.Fill("Multi-precision integers of DSA:"))
		c := pm.mpiDSA()
		for _, l := range c {
			content = append(content, (indent + 1).Fill(l))
		}
		content = append(content, (indent + 2).Fill("-> hash(DSA q bits)"))
	default:
	}
	return content
}

func (pm *PubkeyMPI) mpiRSA() []string {
	var content = make([]string, 0)
	reader := bytes.NewReader(pm.MPI)
	rsaMPI := &RSASigMPI{}
	if err := rsaMPI.Get(reader); err != nil {
		content = append(content, err.Error())
	} else {
		content = append(content, rsaMPI.RSASignature.Dump("RSA m^d mod n", pm.Iflag))
	}
	return content
}

func (pm *PubkeyMPI) mpiDSA() []string {
	var content = make([]string, 0)
	reader := bytes.NewReader(pm.MPI)
	dsaMPI := &DSASigMPI{}
	if err := dsaMPI.Get(reader); err != nil {
		content = append(content, err.Error())
	} else {
		content = append(content, dsaMPI.DSASigR.Dump("DSA r", pm.Iflag))
		content = append(content, dsaMPI.DSASigS.Dump("DSA s", pm.Iflag))
	}
	return content
}

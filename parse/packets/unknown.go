package packets

// Unknown parsing unknown packet.
func Unknown(cxt *Context, indent Indent) ([]string, error) {
	var content = make([]string, 0)
	content = append(content, indent.Fill(cxt.PacketName()))
	return content, nil
}

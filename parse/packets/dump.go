package packets

import "fmt"

// TagName returns tag-name
func TagName(packeType string, tag int, packetSize int, ind int) string {
	if len(Tags) < tag {
		return fmt.Sprintf("%s%s: unknown (tag %d)(%d bytes)", indent(ind), packeType, tag, packetSize)
	}
	return fmt.Sprintf("%s%s: %s (tag %d)(%d bytes)", indent(ind), packeType, Tags[tag], tag, packetSize)
}

func indent(ind int) string {
	indStr := ""
	for i := 0; i < ind; i++ {
		indStr = indStr + "        "
	}
	return indStr
}

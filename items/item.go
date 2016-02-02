package items

//Packets - OpenPGP packets
type Packets struct {
	Packet []*Item
}

//NewPackets returns NewPackets instance
func NewPackets() *Packets {
	return &Packets{}
}

//AddPacket add item in packets.
func (p *Packets) AddPacket(a *Item) {
	p.Packet = append(p.Packet, a)
}

//Item - item in packet
type Item struct {
	Name  string
	Value string
	Dump  string
	Note  string
	Item  []*Item
}

//NewItem returns Item instance
func NewItem(name, value, note string) *Item {
	return &Item{Name: name, Value: value, Note: note}
}

//NewItemDump returns Item instance for dump
func NewItemDump(name, dump, note string) *Item {
	return &Item{Name: name, Dump: dump, Note: note}
}

//AddSub add sub-item in item.
func (i *Item) AddSub(a *Item) {
	i.Item = append(i.Item, a)
}

/*
func (i *Item) String() string {
	if len(i.Dump) > 0 {
		if len(i.Note) > 0 {
			return fmt.Sprintf("%s (%s) - %s", i.Name, i.Note, i.Dump)
		}
		return fmt.Sprintf("%s - %s", i.Name, i.Dump)
	}
	if len(i.Note) > 0 {
		return fmt.Sprintf("%s - %s (%s)", i.Name, i.Value, i.Note)
	}
	return fmt.Sprintf("%s - %s", i.Name, i.Value)
}
*/

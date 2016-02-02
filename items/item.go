package items

import "fmt"

//Item - item in packet
type Item struct {
	Name    string
	Value   string
	Dump    string
	Note    string
	Subitem []*Item
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
	i.Subitem = append(i.Subitem, a)
}

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

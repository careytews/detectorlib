package detectorlib

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	dt "github.com/trustnetworks/analytics-common/datatypes"
	ind "github.com/trustnetworks/indicators"
)

type intRange struct {
	low   int
	high  int
	nodes nodeList
}

type lookupTable struct {
	Strings map[string]nodeList
	Ints    map[int]nodeList
	DNS     map[string]nodeList
	Ranges  []intRange
}

type mapOfIDToNode map[string]*ind.IndicatorNode
type mapOfLookupTables map[string]*lookupTable
type mapOfNodeToIdx map[*ind.IndicatorNode]int
type mapOfIdxToNode map[int]*ind.IndicatorNode
type nodeList []*ind.IndicatorNode

type Detector interface {
	LoadNode(node *ind.IndicatorNode)
	LoadNodes(nodes []*ind.IndicatorNode)
	Lookup(ev *dt.Event) []*dt.Indicator
	PrintState() string
	RemoveNode(node *ind.IndicatorNode)
	GetNumberOfNodes() int
	GetNumberOfNots() int
}

func GetDetector() Detector {
	var det detector
	det.init()
	return &det
}

type detector struct {
	idToNode     mapOfIDToNode     // ID -> node. Only some nodes have IDs.
	lookupTables mapOfLookupTables // Type -> lookup table
	notsMap      mapOfNodeToIdx    // Map of nodes to load order - iterate over to find sibling NOTs
	notsIdxMap   mapOfIdxToNode    // map index of NOT nodes to process at the end

	evID     int
	notIndex int
}

func (det *detector) init() {
	det.idToNode = make(mapOfIDToNode, 0)
	det.lookupTables = make(mapOfLookupTables, 0)
	det.notsMap = make(mapOfNodeToIdx, 0)
	det.notsIdxMap = make(mapOfIdxToNode)
	det.notIndex = 0
}

func (det *detector) GetNumberOfNodes() int {
	return len(det.idToNode)
}

func (det *detector) GetNumberOfNots() int {
	return len(det.notsMap)
}

// IMPORTANT: currently we can only remove entire trees of indicators, not subtrees
// i.e. the node passed to RemoveNode must have no parent, and describe the entire
// tree down to leaf nodes
func (det *detector) RemoveNode(node *ind.IndicatorNode) {
	if len(node.Parents) > 0 {
		log.Error("Trying to remove a node with parents, this is not currently supported")
	}
	// remove each not in turn by iterating through child nodes recursively
	det.removeNode(node)
}

func (det *detector) removeNode(node *ind.IndicatorNode) {
	// 1. remove each node from lookup table (if it has a pattern)
	if node.Pattern != nil {
		det.removeNodeFromLookup(node)
	}
	// 2. remove node from id to node
	if _, ok := det.idToNode[node.ID]; ok {
		delete(det.idToNode, node.ID)
	}
	// 3. if not node remove it from notsMap and notsList
	if node.Operator == "NOT" {
		if idx, ok := det.notsMap[node]; ok {
			delete(det.notsMap, node)
			if _, ok := det.notsIdxMap[idx]; ok {
				delete(det.notsIdxMap, idx)
			}
		}
	}
	// call recursively for children
	for _, c := range node.Children {
		det.removeNode(c)
	}
}

func (det *detector) removeNodeFromLookup(node *ind.IndicatorNode) {
	if tables, ok := det.lookupTables[node.Pattern.Type]; ok {
		if node.Pattern.Match == "range" {
			// can ignore errors as the Indicator would never have been added
			// if it had errors
			v1, _ := strconv.Atoi(node.Pattern.Value)
			v2, _ := strconv.Atoi(node.Pattern.Value2)
			var low int
			var high int
			if v1 > v2 {
				high = v1
				low = v2
			} else {
				low = v1
				high = v2
			}
			for rangeIndex, lookup := range tables.Ranges {
				if lookup.low == low && lookup.high == high {
					// remove node id from list
					for nodeIndex, n := range lookup.nodes {
						if n == node {
							lookup.nodes = append(lookup.nodes[:nodeIndex], lookup.nodes[nodeIndex+1:]...)
							break
						}
					}
					// if node list is now empty remove the range from range list
					if len(lookup.nodes) == 0 {
						tables.Ranges = append(tables.Ranges[:rangeIndex], tables.Ranges[rangeIndex+1:]...)
					}
					break
				}
			}
		} else if node.Pattern.Match == "int" {
			val, _ := strconv.Atoi(node.Pattern.Value)
			if nList, ok := tables.Ints[val]; ok {
				for nodeIndex, n := range nList {
					if n == node {
						nList = append(nList[:nodeIndex], nList[nodeIndex+1:]...)
						if len(nList) == 0 {
							delete(tables.Ints, val)
						} else {
							tables.Ints[val] = nList
						}
						break
					}
				}
			}
		} else if node.Pattern.Match == "dns" {
			if nList, ok := tables.DNS[node.Pattern.Value]; ok {
				for nodeIndex, n := range nList {
					if n == node {
						nList = append(nList[:nodeIndex], nList[nodeIndex+1:]...)
						if len(nList) == 0 {
							delete(tables.DNS, node.Pattern.Value)
						} else {
							tables.DNS[node.Pattern.Value] = nList
						}
						break
					}
				}
			}
		} else {
			if nList, ok := tables.Strings[node.Pattern.Value]; ok {
				for nodeIndex, n := range nList {
					if n == node {
						nList = append(nList[:nodeIndex], nList[nodeIndex+1:]...)
						if len(nList) == 0 {
							delete(tables.Strings, node.Pattern.Value)
						} else {
							tables.Strings[node.Pattern.Value] = nList
						}
						break
					}
				}
			}
		}
	}
}

func (det *detector) PrintState() string {
	var s string
	for k, v := range det.lookupTables {
		s += fmt.Sprint("  ", k, "\n")
		s += fmt.Sprint("  ", v.Strings, "\n")
		s += fmt.Sprint("  ", v.Ints, "\n")
		s += fmt.Sprint("  ", v.DNS, "\n")
		s += fmt.Sprint("  ", v.Ranges, "\n")
	}
	s += "\n---\n"
	s += fmt.Sprint(det.idToNode)
	return s
}

func (det *detector) LoadNode(node *ind.IndicatorNode) {
	det.loadNode(node, nil)
	det.findSiblingNOTs()
}

func (det *detector) LoadNodes(nodes []*ind.IndicatorNode) {
	for _, node := range nodes {
		det.loadNode(node, nil)
	}
	det.findSiblingNOTs()
}

func (det *detector) loadNode(node *ind.IndicatorNode, parent *ind.IndicatorNode) {

	if node == nil {
		return
	}

	if node.ID != "" {
		// Check ID does not already exist in the ID map
		if _, exists := det.idToNode[node.ID]; exists {
			log.Warnf("Duplicate node ID %s", node.ID)
			return
		}

		// Store node in the ID map. This allows other nodes to reference this.
		det.idToNode[node.ID] = node
	}

	if node.Indicator != nil && node.Indicator.Value != "" {
		node.UseOriginalIndicatorValue = true
	}

	// Store in the pattern map (if node has a pattern)
	if node.Pattern != nil {

		lookupTab := det.lookupTables[node.Pattern.Type]
		if lookupTab == nil {
			lookupTab = new(lookupTable)
			det.lookupTables[node.Pattern.Type] = lookupTab
		}

		if node.Pattern.Match == "" || node.Pattern.Match == "string" {
			if lookupTab.Strings == nil {
				lookupTab.Strings = make(map[string]nodeList)
			}

			lookupTab.Strings[node.Pattern.Value] =
				append(lookupTab.Strings[node.Pattern.Value], node)

		} else if node.Pattern.Match == "dns" {
			if lookupTab.DNS == nil {
				lookupTab.DNS = make(map[string]nodeList)
			}

			lookupTab.DNS[node.Pattern.Value] =
				append(lookupTab.DNS[node.Pattern.Value], node)

		} else if node.Pattern.Match == "int" {

			val, err := strconv.Atoi(node.Pattern.Value)
			if err == nil {
				if lookupTab.Ints == nil {
					lookupTab.Ints = make(map[int]nodeList)
				}

				lookupTab.Ints[val] =
					append(lookupTab.Ints[val], node)
			} else {
				log.Warnf("Value %v is not an int", node.Pattern.Value)
			}

		} else if node.Pattern.Match == "range" {

			low, err1 := strconv.Atoi(node.Pattern.Value)
			high, err2 := strconv.Atoi(node.Pattern.Value2)
			if err1 == nil && err2 == nil {
				irange := intRange{
					low:  low,
					high: high,
				}
				irange.nodes = append(irange.nodes, node)
				lookupTab.Ranges = append(lookupTab.Ranges, irange)
			} else {
				log.Warnf("One or both of %v and %v are not ints",
					node.Pattern.Value, node.Pattern.Value2)
			}
		} else {
			log.Warnf("Invalid match type: %v", node.Pattern.Match)
		}
	}

	// Add a link up to parent (if it has one)
	if parent != nil {
		node.Parents = append(node.Parents, parent)
	}

	// Load this node's children (if it has any)
	for idx, child := range node.Children {

		if child.Ref != "" {
			concreteChild := det.idToNode[child.Ref]

			if concreteChild != nil {

				// Replace this child with the real node
				node.Children[idx] = concreteChild

				// Add link from child to this node (a parent)
				concreteChild.Parents = append(concreteChild.Parents, node)
			} else {
				log.Warnf("Could not find referenced node %s", child.Ref)
			}
		} else {
			det.loadNode(child, node)
		}
	}

	// Store the NOT nodes in leaf->node order so we can process them
	// at the end of the lookup
	if node.Operator == "NOT" {
		det.notsIdxMap[det.notIndex] = node
		det.notsMap[node] = det.notIndex
		det.notIndex += 1
	}

}

// Check every NOT and add itself to it's siblings' list
// This is used as a way to reduce the number of NOTs we need to check at the end of an event
func (det *detector) findSiblingNOTs() {
	// Iterate over every node
	for notNode, idx := range det.notsMap {
		// Check every parent
		for _, parent := range notNode.Parents {
			for _, sibling := range parent.Children {
				if sibling != notNode {
					// Find sibling in NOTs list
					sibling.SiblingNots = append(sibling.SiblingNots, idx)
				}
			}
		}
	}
}

func (det *detector) fireNodes(nodes nodeList, indicators *[]*dt.Indicator, pRelevantNotsList *[]int) {
	for _, node := range nodes {
		*pRelevantNotsList = append(*pRelevantNotsList, node.SiblingNots...)

		newInds, newNotNodes := node.Fire(det.evID)
		if newInds != nil {
			*indicators = append(*indicators, newInds...)
		}
		if newNotNodes != nil {
			*pRelevantNotsList = append(*pRelevantNotsList, newNotNodes...)
		}
	}
}

func (det *detector) matchString(t string, v string, indicators *[]*dt.Indicator, pRelevantNotsList *[]int) {

	if lookupTable, ok := det.lookupTables[t]; ok {
		if lookupTable.Strings != nil {
			if nodes, ok := lookupTable.Strings[v]; ok {
				det.fireNodes(nodes, indicators, pRelevantNotsList)
			}
		}
	}
}

func (det *detector) matchInt(t string, v int, indicators *[]*dt.Indicator, pRelevantNotsList *[]int) {

	if lookupTable, ok := det.lookupTables[t]; ok {

		// Check explicit ints
		if lookupTable.Ints != nil {
			if nodes, ok := lookupTable.Ints[v]; ok {
				det.fireNodes(nodes, indicators, pRelevantNotsList)
			}
		}

		// Check int ranges
		if lookupTable.Ranges != nil {
			for _, irange := range lookupTable.Ranges {
				if v >= irange.low && v <= irange.high {
					det.fireNodes(irange.nodes, indicators, pRelevantNotsList)
				}
			}
		}
	}
}

func (det *detector) matchDNS(t string, hostname string, indicators *[]*dt.Indicator, pRelevantNotsList *[]int) {

	if lookupTable, ok := det.lookupTables[t]; ok {
		if lookupTable.DNS != nil {

			// Start with the tld then add in the rest,
			// testing for a match each time
			parts := strings.Split(hostname, ".")
			if len(parts) > 1 {
				name := parts[len(parts)-1] // tld
				for p := len(parts) - 2; p >= 0; p-- {
					name = parts[p] + "." + name
					if nodes, ok := lookupTable.DNS[name]; ok {
						det.fireNodes(nodes, indicators, pRelevantNotsList)
					}
				}
			}
		}
	}
}

func (det *detector) Lookup(ev *dt.Event) []*dt.Indicator {

	var indicators []*dt.Indicator
	var relevantNotsList []int

	det.evID++

	// Look at source addresses
	for _, str := range ev.Src {

		if strings.HasPrefix(str, "ipv4:") {
			addr := str[5:]
			det.matchString("src.ipv4", addr, &indicators, &relevantNotsList)
		} else if strings.HasPrefix(str, "ipv6:") {
			addr := str[5:]
			det.matchString("src.ipv6", addr, &indicators, &relevantNotsList)
		} else if strings.HasPrefix(str, "tcp:") {
			if port, err := strconv.Atoi(str[4:]); err == nil {
				det.matchInt("src.tcp", port, &indicators, &relevantNotsList)
			}
		} else if strings.HasPrefix(str, "udp:") {
			if port, err := strconv.Atoi(str[4:]); err == nil {
				det.matchInt("src.udp", port, &indicators, &relevantNotsList)
			}
		}
	}

	// Look at dest addresses
	for _, str := range ev.Dest {

		if strings.HasPrefix(str, "ipv4:") {
			addr := str[5:]
			det.matchString("dest.ipv4", addr, &indicators, &relevantNotsList)
		} else if strings.HasPrefix(str, "ipv6:") {
			addr := str[5:]
			det.matchString("dest.ipv6", addr, &indicators, &relevantNotsList)
		} else if strings.HasPrefix(str, "tcp:") {
			if port, err := strconv.Atoi(str[4:]); err == nil {
				det.matchInt("dest.tcp", port, &indicators, &relevantNotsList)
			}
		} else if strings.HasPrefix(str, "udp:") {
			if port, err := strconv.Atoi(str[4:]); err == nil {
				det.matchInt("dest.udp", port, &indicators, &relevantNotsList)
			}
		}
	}

	// Look in DNS queries for hostname IOCs
	if ev.DnsMessage != nil && ev.DnsMessage.Query != nil {
		for _, query := range ev.DnsMessage.Query {
			det.matchDNS("hostname", query.Name, &indicators, &relevantNotsList)
		}
	}

	// Look in DNS answers for hostname IOCs
	if ev.DnsMessage != nil && ev.DnsMessage.Answer != nil {
		for _, answer := range ev.DnsMessage.Answer {
			det.matchDNS("hostname", answer.Name, &indicators, &relevantNotsList)
		}
	}

	// If there's an HTTP header, look at the Host field.
	if ev.HttpRequest != nil {
		if host, ok := ev.HttpRequest.Header["Host"]; ok {
			det.matchDNS("hostname", host, &indicators, &relevantNotsList)
		}
		if ua, ok := ev.HttpRequest.Header["User-Agent"]; ok {
			det.matchString("useragent", ua, &indicators, &relevantNotsList)
		}
	}

	// URL IOCs
	if ev.Url != "" {
		det.matchString("url", ev.Url, &indicators, &relevantNotsList)

		// If URL has params then try without
		if idx := strings.IndexByte(ev.Url, '?'); idx >= 0 {
			urlWithoutParams := ev.Url[:idx]
			det.matchString("url", urlWithoutParams, &indicators, &relevantNotsList)
		}
	}

	// Country IOC
	if ev.Location != nil {
		if ev.Location.Src != nil {
			det.matchString("src.country", ev.Location.Src.Country, &indicators, &relevantNotsList)
		}
		if ev.Location.Dest != nil {
			det.matchString("dest.country", ev.Location.Dest.Country, &indicators, &relevantNotsList)
		}
	}

	// If we have an NTP private, check its mode
	if ev.NtpPrivate != nil {
		det.matchInt("ntpmode", ev.NtpPrivate.Mode, &indicators, &relevantNotsList)
	}

	// Other matches
	det.matchString("device", ev.Device, &indicators, &relevantNotsList)
	det.matchString("network", ev.Network, &indicators, &relevantNotsList)

	// Resolve any unresolved NOT nodes
	done := -1

startNotResolve:
	// First sort NOT list
	sort.Ints(relevantNotsList)

	for idx, notNodeIdx := range relevantNotsList {
		if notNodeIdx != done {
			node, ok := det.notsIdxMap[notNodeIdx]
			if ok {
				newInds, newNotNodes := node.ResolveNot(det.evID)
				// Set notNodeIdx to -1 so we don't repeatedly process it
				relevantNotsList[idx] = done

				if newInds != nil {
					indicators = append(indicators, newInds...)
				}
				if newNotNodes != nil {
					relevantNotsList = append(relevantNotsList, newNotNodes...)
					goto startNotResolve
				}
			}
		}
	}

	return indicators
}

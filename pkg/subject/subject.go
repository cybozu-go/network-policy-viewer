package subject

import "fmt"

const (
	GroupAll       = "all"
	GroupNamespace = "namespace"
	GroupPod       = "pod"
)

type SelectorConfig struct {
	AllNamespaces bool
	Namespace     string
	PodSelector   string
	Node          string
}

var (
	group          string
	selectorConfig *SelectorConfig
)

func init() {
	group = GroupPod
}

func GetGroup() string {
	return group
}

func SetGroup(g string) error {
	switch g {
	case "a", "all":
		g = GroupAll
	case "n", "ns", "namespace", "namespaces":
		g = GroupNamespace
	case "p", "po", "pod", "pods", "":
		g = GroupPod
	default:
		return fmt.Errorf("failed to parse --group: should be one of: all [a], ns [n], pod [p]")
	}
	group = g
	return nil
}

func GetSelectorConfig() *SelectorConfig {
	return selectorConfig
}

func SetSelectorConfig(c *SelectorConfig) {
	selectorConfig = c
}

package changelog

import (
	"strings"
	"testing"

	"github.com/nning/juist/types"
)

func TestEveryKindIsNamed(t *testing.T) {
	for k := types.Kind(1); k != 0; k++ {
		if strings.HasPrefix(k.String(), "kind?") {
			continue
		}
		if _, ok := kindNames[k]; !ok {
			t.Errorf("%v has no name", k)
		}
	}
}

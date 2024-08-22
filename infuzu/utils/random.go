package infuzu

import (
	"github.com/google/uuid"
	"strings"
)

func CreateUUIDWithoutDash() string {
	uuidWithDashes := uuid.New().String()
	return strings.ReplaceAll(uuidWithDashes, "-", "")
}

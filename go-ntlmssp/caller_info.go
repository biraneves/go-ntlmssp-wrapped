package ntlmssp

import (
	"fmt"
	"runtime"
)

func CallerInfo() string {
	pc, file, line, ok := runtime.Caller(1)
	if !ok {
		return "unknown"
	}

	fn := runtime.FuncForPC(pc)
	return fmt.Sprintf("[%s:%d][%s]", file, line, fn.Name())
}

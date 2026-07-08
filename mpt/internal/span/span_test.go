package span

import (
	"fmt"
	"testing"
	"time"
)

func BenchmarkReserveRelease(b *testing.B) {
	for _, shift := range []int{20, 24, 28, 30, 32, 34, 36, 38, 40, 44} {
		size := 1 << shift
		name := fmt.Sprintf("size=%dMB", size>>20)
		if size >= 1<<30 {
			name = fmt.Sprintf("size=%dGB", size>>30)
		}
		if size >= 1<<40 {
			name = fmt.Sprintf("size=%dTB", size>>40)
		}
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(size))
			for b.Loop() {
				start := time.Now()
				s, err := Reserve(size)
				println("A", time.Since(start).String())
				if err != nil {
					b.Fatal(err)
				}
				s.Release()
				println("B", time.Since(start).String())
				s.UnsafeUnmap()
				println("C", time.Since(start).String())
			}
		})
	}
}

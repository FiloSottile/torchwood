// Package tesserax implements additional functions for use with the [tessera]
// package. It is a separate package to prevent all torchwood importers from
// incurring a transitive dependency on tessera.
package tesserax

import (
	"context"
	"errors"
	"fmt"

	"filippo.io/torchwood"
	"github.com/transparency-dev/tessera"
	"golang.org/x/mod/sumdb/tlog"
)

// TileReader is a [torchwood.TileReader] implemented by a [tessera.LogReader].
type TileReader struct {
	r tessera.LogReader
}

var _ torchwood.TileReader = (*TileReader)(nil)

// NewTileReader returns a TileReader that reads tiles and checkpoints from the
// given tessera.LogReader.
func NewTileReader(r tessera.LogReader) *TileReader {
	return &TileReader{r: r}
}

// ReadTiles implements [torchwood.TileReader.ReadTiles].
func (tr *TileReader) ReadTiles(ctx context.Context, tiles []tlog.Tile) (data [][]byte, err error) {
	data = make([][]byte, len(tiles))
	for i, t := range tiles {
		if t.H != torchwood.TileHeight {
			return nil, errors.New("unsupported tile height")
		}
		if t.L < -1 {
			return nil, errors.New("invalid tile level")
		}
		if t.L == -1 {
			index, partial := uint64(t.N), uint8(t.W)
			tileData, err := tr.r.ReadEntryBundle(ctx, index, partial)
			if err != nil {
				return nil, fmt.Errorf("failed to read tessera entry bundle index=%d, partial=%d: %w", index, partial, err)
			}
			data[i] = tileData
			continue
		}
		level, index, partial := uint64(t.L), uint64(t.N), uint8(t.W)
		tileData, err := tr.r.ReadTile(ctx, level, index, partial)
		if err != nil {
			return nil, fmt.Errorf("failed to read tessera tile level=%d, index=%d, partial=%d: %w", level, index, partial, err)
		}
		data[i] = tileData
	}
	return data, nil
}

// SaveTiles is a no-op implementation of [torchwood.TileReader.SaveTiles].
func (tr *TileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

// ReadEndpoint exposes the "checkpoint" endpoint via
// [tessera.LogReader.ReadCheckpoint].
func (tr *TileReader) ReadEndpoint(ctx context.Context, path string) ([]byte, error) {
	if path != "checkpoint" {
		return nil, errors.New("unsupported endpoint: " + path)
	}
	return tr.r.ReadCheckpoint(ctx)
}

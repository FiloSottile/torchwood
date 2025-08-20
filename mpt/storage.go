package mpt

import (
	"context"
	"errors"
	"slices"
)

type Storage interface {
	// Load retrieves the node with the given label.
	Load(ctx context.Context, label Label) (*Node, error)

	// LoadPath loads the siblings of the path to reach the given node
	// (intuitively, the inclusion proof). If the node is not present, the
	// sequence stops with what would be its sibling if it were present. The
	// returned nodes are ordered from the node sibling up to the root's child.
	LoadPath(ctx context.Context, label Label) ([]*Node, error)

	// Store stores the given nodes. If a node with the same label already
	// exists, it is replaced. The nodes can be in any order.
	Store(ctx context.Context, nodes ...*Node) error
}

type memoryStorage struct {
	nodes map[Label]*Node
}

func NewMemoryStorage() Storage {
	return &memoryStorage{
		nodes: make(map[Label]*Node),
	}
}

var ErrNodeNotFound = errors.New("node not found")

func (s *memoryStorage) Load(ctx context.Context, label Label) (*Node, error) {
	if node, ok := s.nodes[label]; ok {
		return node, nil
	}
	return nil, ErrNodeNotFound
}

func (s *memoryStorage) LoadPath(ctx context.Context, label Label) ([]*Node, error) {
	var nodes []*Node
	node := s.nodes[RootLabel]
	for node.Label != label {
		if !label.HasPrefix(node.Label) {
			if node.Label != EmptyNodeLabel {
				nodes = append(nodes, node)
			}
			break
		}
		switch label.SideOf(node.Label) {
		case Left:
			nodes = append(nodes, s.nodes[node.Right])
			node = s.nodes[node.Left]
		case Right:
			nodes = append(nodes, s.nodes[node.Left])
			node = s.nodes[node.Right]
		}
	}
	slices.Reverse(nodes)
	return nodes, nil
}

func (s *memoryStorage) Store(ctx context.Context, nodes ...*Node) error {
	for _, node := range nodes {
		s.nodes[node.Label] = node
	}
	return nil
}

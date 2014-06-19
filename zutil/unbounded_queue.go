package zutil

import (
	"net"
)

type UnboundedQueue interface {
	Push(net.IP)
	Pop() net.IP
	Size() int
}

type unboundedRing struct {
	elts []net.IP
	front, size int
}

func NewUnboundedRing(initialCapacity int) UnboundedQueue {
	ur := unboundedRing{elts: make([]net.IP, initialCapacity), front: 0, size: 0}
	return &ur
}

func (ur *unboundedRing) grow() {
	// Allocate a new backing array
	newSlice := make([]net.IP, 2*ur.size)
	// Copy from the front of the queue through the end of the array
	copy(newSlice, ur.elts[ur.front:])
	// Copy from the front of the slice through the front of the queue
	copy(newSlice[ur.size - ur.front:], ur.elts[0:ur.front])
	// Fix the bookeeping, size stays the same
	ur.elts = newSlice
	ur.front = 0
}

func (ur *unboundedRing) Size() int {
	return ur.size
}

func (ur *unboundedRing) Push(qe net.IP) {
	if ur.size == len(ur.elts) {
		ur.grow()
	}
	if !(ur.size < len(ur.elts)) {
		panic(ur.size)
	}
	back := (ur.front + ur.size) % len(ur.elts)
	ur.elts[back] = qe
	ur.size++
}

func (ur *unboundedRing) Pop() net.IP {
	if !(ur.size > 0) {
		panic(ur.size)
	}
	toRemove := ur.elts[ur.front]
	ur.front = (ur.front + 1) % len(ur.elts)
	ur.size--
	return toRemove
}


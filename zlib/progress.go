package zlib

type GrabProgress struct {
	success uint
	failure uint
}

func (gp *GrabProgress) Success() uint {
	return gp.success
}

func (gp *GrabProgress) Failure() uint {
	return gp.failure
}

package ratelimit

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

// Reader wraps a buf.Reader with rate limiting
type Reader struct {
	reader  buf.Reader
	limiter *rate.Limiter
}

// NewReader creates a rate-limited reader
func NewReader(reader buf.Reader, bytesPerSecond int64) buf.Reader {
	if bytesPerSecond <= 0 || reader == nil {
		return reader
	}

	// Safe burst size calculation - cap at 10MB to prevent overflow
	burstSize := int(bytesPerSecond)
	if bytesPerSecond > 10485760 {
		burstSize = 10485760
	}
	if burstSize < 4096 {
		burstSize = 4096
	}

	return &Reader{
		reader:  reader,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSecond), burstSize),
	}
}

// ReadMultiBuffer implements buf.Reader
func (r *Reader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r == nil || r.reader == nil {
		return nil, io.ErrClosedPipe
	}

	mb, err := r.reader.ReadMultiBuffer()
	if err != nil {
		return mb, err
	}

	// Apply rate limiting after reading
	totalBytes := int(mb.Len())
	if totalBytes > 0 && r.limiter != nil {
		ctx := context.Background()
		if waitErr := r.limiter.WaitN(ctx, totalBytes); waitErr != nil {
			buf.ReleaseMulti(mb)
			return nil, waitErr
		}
	}

	return mb, nil
}

// Writer wraps a buf.Writer with rate limiting
type Writer struct {
	writer  buf.Writer
	limiter *rate.Limiter
}

// NewWriter creates a rate-limited writer
func NewWriter(writer buf.Writer, bytesPerSecond int64) buf.Writer {
	if bytesPerSecond <= 0 || writer == nil {
		return writer
	}

	// Safe burst size calculation - cap at 10MB to prevent overflow
	burstSize := int(bytesPerSecond)
	if bytesPerSecond > 10485760 {
		burstSize = 10485760
	}
	if burstSize < 4096 {
		burstSize = 4096
	}

	return &Writer{
		writer:  writer,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSecond), burstSize),
	}
}

// WriteMultiBuffer implements buf.Writer
func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w == nil || w.writer == nil {
		return io.ErrClosedPipe
	}

	// Apply rate limiting before writing
	totalBytes := int(mb.Len())
	if totalBytes > 0 && w.limiter != nil {
		ctx := context.Background()
		if waitErr := w.limiter.WaitN(ctx, totalBytes); waitErr != nil {
			return waitErr
		}
	}

	return w.writer.WriteMultiBuffer(mb)
}

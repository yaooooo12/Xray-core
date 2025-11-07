package trojan

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

// rateLimitedReader wraps a buf.Reader with rate limiting
type rateLimitedReader struct {
	reader  buf.Reader
	limiter *rate.Limiter
}

// newRateLimitedReader creates a rate-limited reader
func newRateLimitedReader(reader buf.Reader, bytesPerSecond int64) buf.Reader {
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

	return &rateLimitedReader{
		reader:  reader,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSecond), burstSize),
	}
}

// ReadMultiBuffer implements buf.Reader
func (r *rateLimitedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
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

// rateLimitedWriter wraps a buf.Writer with rate limiting
type rateLimitedWriter struct {
	writer  buf.Writer
	limiter *rate.Limiter
}

// newRateLimitedWriter creates a rate-limited writer
func newRateLimitedWriter(writer buf.Writer, bytesPerSecond int64) buf.Writer {
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

	return &rateLimitedWriter{
		writer:  writer,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSecond), burstSize),
	}
}

// WriteMultiBuffer implements buf.Writer
func (w *rateLimitedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
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

// rateLimitedConn wraps an io.ReadWriteCloser with rate limiting
type rateLimitedConn struct {
	conn         io.ReadWriteCloser
	readLimiter  *rate.Limiter
	writeLimiter *rate.Limiter
}

// newRateLimitedConn creates a rate-limited connection
func newRateLimitedConn(conn io.ReadWriteCloser, uploadSpeed, downloadSpeed int64) io.ReadWriteCloser {
	if conn == nil || (uploadSpeed <= 0 && downloadSpeed <= 0) {
		return conn
	}

	rlConn := &rateLimitedConn{conn: conn}

	if uploadSpeed > 0 {
		// Safe burst size - cap at 10MB
		burstSize := int(uploadSpeed)
		if uploadSpeed > 10485760 {
			burstSize = 10485760
		}
		if burstSize < 4096 {
			burstSize = 4096
		}
		rlConn.readLimiter = rate.NewLimiter(rate.Limit(uploadSpeed), burstSize)
	}

	if downloadSpeed > 0 {
		// Safe burst size - cap at 10MB
		burstSize := int(downloadSpeed)
		if downloadSpeed > 10485760 {
			burstSize = 10485760
		}
		if burstSize < 4096 {
			burstSize = 4096
		}
		rlConn.writeLimiter = rate.NewLimiter(rate.Limit(downloadSpeed), burstSize)
	}

	return rlConn
}

// Read implements io.Reader
func (c *rateLimitedConn) Read(p []byte) (n int, err error) {
	if c == nil || c.conn == nil {
		return 0, io.ErrClosedPipe
	}

	n, err = c.conn.Read(p)
	if n > 0 && c.readLimiter != nil {
		ctx := context.Background()
		_ = c.readLimiter.WaitN(ctx, n)
	}
	return n, err
}

// Write implements io.Writer
func (c *rateLimitedConn) Write(p []byte) (n int, err error) {
	if c == nil || c.conn == nil {
		return 0, io.ErrClosedPipe
	}

	if len(p) > 0 && c.writeLimiter != nil {
		ctx := context.Background()
		if waitErr := c.writeLimiter.WaitN(ctx, len(p)); waitErr != nil {
			return 0, waitErr
		}
	}
	return c.conn.Write(p)
}

// Close implements io.Closer
func (c *rateLimitedConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

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
	if bytesPerSecond <= 0 {
		return reader
	}
	return &rateLimitedReader{
		reader:  reader,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSecond), int(bytesPerSecond)),
	}
}

// ReadMultiBuffer implements buf.Reader
func (r *rateLimitedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil {
		return mb, err
	}

	// Apply rate limiting after reading
	totalBytes := int(mb.Len())
	if totalBytes > 0 && r.limiter != nil {
		if err := r.limiter.WaitN(context.Background(), totalBytes); err != nil {
			buf.ReleaseMulti(mb)
			return nil, err
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
	if bytesPerSecond <= 0 {
		return writer
	}
	return &rateLimitedWriter{
		writer:  writer,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSecond), int(bytesPerSecond)),
	}
}

// WriteMultiBuffer implements buf.Writer
func (w *rateLimitedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	// Apply rate limiting before writing
	totalBytes := int(mb.Len())
	if totalBytes > 0 && w.limiter != nil {
		if err := w.limiter.WaitN(context.Background(), totalBytes); err != nil {
			return err
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
	if uploadSpeed <= 0 && downloadSpeed <= 0 {
		return conn
	}

	rlConn := &rateLimitedConn{conn: conn}

	if uploadSpeed > 0 {
		rlConn.readLimiter = rate.NewLimiter(rate.Limit(uploadSpeed), int(uploadSpeed))
	}

	if downloadSpeed > 0 {
		rlConn.writeLimiter = rate.NewLimiter(rate.Limit(downloadSpeed), int(downloadSpeed))
	}

	return rlConn
}

// Read implements io.Reader
func (c *rateLimitedConn) Read(p []byte) (n int, err error) {
	n, err = c.conn.Read(p)
	if n > 0 && c.readLimiter != nil {
		_ = c.readLimiter.WaitN(context.Background(), n)
	}
	return n, err
}

// Write implements io.Writer
func (c *rateLimitedConn) Write(p []byte) (n int, err error) {
	if len(p) > 0 && c.writeLimiter != nil {
		if err := c.writeLimiter.WaitN(context.Background(), len(p)); err != nil {
			return 0, err
		}
	}
	return c.conn.Write(p)
}

// Close implements io.Closer
func (c *rateLimitedConn) Close() error {
	return c.conn.Close()
}

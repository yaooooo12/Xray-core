package ratelimit

import (
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"golang.org/x/time/rate"
)

// RateLimitedReader wraps a buf.Reader with rate limiting
type RateLimitedReader struct {
	reader  buf.Reader
	limiter *rate.Limiter
}

// NewRateLimitedReader creates a new rate-limited reader
// bytesPerSecond: maximum bytes per second, 0 means unlimited
func NewRateLimitedReader(reader buf.Reader, bytesPerSecond int64) buf.Reader {
	if bytesPerSecond <= 0 {
		return reader
	}

	return &RateLimitedReader{
		reader:  reader,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSecond), int(bytesPerSecond)),
	}
}

// ReadMultiBuffer reads data with rate limiting
func (r *RateLimitedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.reader.ReadMultiBuffer()
	if err != nil {
		return mb, err
	}

	// Calculate total bytes read
	totalBytes := int64(mb.Len())
	if totalBytes > 0 {
		// Reserve tokens from the rate limiter
		// This will block if the rate limit is exceeded
		ctx := context.Background()
		reservation := r.limiter.ReserveN(time.Now(), int(totalBytes))
		if !reservation.OK() {
			// If we can't get tokens immediately, wait
			delay := reservation.Delay()
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
					// Rate limit delay completed
				case <-ctx.Done():
					timer.Stop()
					return mb, ctx.Err()
				}
			}
		}
	}

	return mb, nil
}

// RateLimitedWriter wraps a buf.Writer with rate limiting
type RateLimitedWriter struct {
	writer  buf.Writer
	limiter *rate.Limiter
}

// NewRateLimitedWriter creates a new rate-limited writer
// bytesPerSecond: maximum bytes per second, 0 means unlimited
func NewRateLimitedWriter(writer buf.Writer, bytesPerSecond int64) buf.Writer {
	if bytesPerSecond <= 0 {
		return writer
	}

	return &RateLimitedWriter{
		writer:  writer,
		limiter: rate.NewLimiter(rate.Limit(bytesPerSecond), int(bytesPerSecond)),
	}
}

// WriteMultiBuffer writes data with rate limiting
func (w *RateLimitedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	// Calculate total bytes to write
	totalBytes := int64(mb.Len())
	if totalBytes > 0 {
		// Reserve tokens from the rate limiter
		ctx := context.Background()
		reservation := w.limiter.ReserveN(time.Now(), int(totalBytes))
		if !reservation.OK() {
			// If we can't get tokens immediately, wait
			delay := reservation.Delay()
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
					// Rate limit delay completed
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				}
			}
		}
	}

	return w.writer.WriteMultiBuffer(mb)
}

// RateLimitedConn wraps an io.ReadWriteCloser with rate limiting for both read and write
type RateLimitedConn struct {
	conn          io.ReadWriteCloser
	readLimiter   *rate.Limiter
	writeLimiter  *rate.Limiter
	uploadSpeed   int64
	downloadSpeed int64
}

// NewRateLimitedConn creates a new rate-limited connection wrapper
func NewRateLimitedConn(conn io.ReadWriteCloser, uploadSpeed, downloadSpeed int64) io.ReadWriteCloser {
	if uploadSpeed <= 0 && downloadSpeed <= 0 {
		return conn
	}

	rlConn := &RateLimitedConn{
		conn:          conn,
		uploadSpeed:   uploadSpeed,
		downloadSpeed: downloadSpeed,
	}

	if uploadSpeed > 0 {
		rlConn.readLimiter = rate.NewLimiter(rate.Limit(uploadSpeed), int(uploadSpeed))
	}

	if downloadSpeed > 0 {
		rlConn.writeLimiter = rate.NewLimiter(rate.Limit(downloadSpeed), int(downloadSpeed))
	}

	return rlConn
}

// Read implements io.Reader with upload rate limiting
func (c *RateLimitedConn) Read(p []byte) (n int, err error) {
	if c.readLimiter != nil {
		// Wait for permission to read
		ctx := context.Background()
		maxRead := len(p)
		if maxRead > int(c.uploadSpeed) {
			maxRead = int(c.uploadSpeed)
		}

		reservation := c.readLimiter.ReserveN(time.Now(), maxRead)
		if !reservation.OK() {
			delay := reservation.Delay()
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return 0, ctx.Err()
				}
			}
		}
	}

	n, err = c.conn.Read(p)
	return n, err
}

// Write implements io.Writer with download rate limiting
func (c *RateLimitedConn) Write(p []byte) (n int, err error) {
	if c.writeLimiter != nil {
		// Wait for permission to write
		ctx := context.Background()
		toWrite := len(p)

		reservation := c.writeLimiter.ReserveN(time.Now(), toWrite)
		if !reservation.OK() {
			delay := reservation.Delay()
			if delay > 0 {
				timer := time.NewTimer(delay)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return 0, ctx.Err()
				}
			}
		}
	}

	n, err = c.conn.Write(p)
	return n, err
}

// Close implements io.Closer
func (c *RateLimitedConn) Close() error {
	return c.conn.Close()
}

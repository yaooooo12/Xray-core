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
	// Return original connection if no rate limiting needed or if conn is nil
	if conn == nil || (uploadSpeed <= 0 && downloadSpeed <= 0) {
		return conn
	}

	rlConn := &RateLimitedConn{
		conn:          conn,
		uploadSpeed:   uploadSpeed,
		downloadSpeed: downloadSpeed,
	}

	if uploadSpeed > 0 {
		// Use a reasonable burst size (min 4KB, max 128KB)
		// Cap the speed to prevent overflow when converting to int
		cappedSpeed := uploadSpeed
		if cappedSpeed > 131072 {
			cappedSpeed = 131072
		}
		burstSize := int(cappedSpeed)
		if burstSize < 4096 {
			burstSize = 4096 // Min 4KB
		}
		rlConn.readLimiter = rate.NewLimiter(rate.Limit(uploadSpeed), burstSize)
	}

	if downloadSpeed > 0 {
		// Use a reasonable burst size (min 4KB, max 128KB)
		// Cap the speed to prevent overflow when converting to int
		cappedSpeed := downloadSpeed
		if cappedSpeed > 131072 {
			cappedSpeed = 131072
		}
		burstSize := int(cappedSpeed)
		if burstSize < 4096 {
			burstSize = 4096 // Min 4KB
		}
		rlConn.writeLimiter = rate.NewLimiter(rate.Limit(downloadSpeed), burstSize)
	}

	return rlConn
}

// Read implements io.Reader with upload rate limiting
func (c *RateLimitedConn) Read(p []byte) (n int, err error) {
	// Safety check
	if c == nil || c.conn == nil {
		return 0, io.ErrClosedPipe
	}

	// First, do the actual read
	n, err = c.conn.Read(p)
	if err != nil || n <= 0 {
		return n, err
	}

	// Then apply rate limiting based on bytes actually read
	if c.readLimiter != nil {
		ctx := context.Background()
		// Wait for tokens based on actual bytes read
		waitErr := c.readLimiter.WaitN(ctx, n)
		if waitErr != nil {
			return n, waitErr
		}
	}

	return n, err
}

// Write implements io.Writer with download rate limiting
func (c *RateLimitedConn) Write(p []byte) (n int, err error) {
	// Safety check
	if c == nil || c.conn == nil {
		return 0, io.ErrClosedPipe
	}

	// Apply rate limiting before write for download (server to client)
	if c.writeLimiter != nil && len(p) > 0 {
		ctx := context.Background()
		// Wait for tokens before writing
		waitErr := c.writeLimiter.WaitN(ctx, len(p))
		if waitErr != nil {
			return 0, waitErr
		}
	}

	n, err = c.conn.Write(p)
	return n, err
}

// Close implements io.Closer
func (c *RateLimitedConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

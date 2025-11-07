package ratelimit

import (
	"context"
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

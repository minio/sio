// Copyright (C) 2017 Minio Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sio

import "io"

type decWriterV1 struct {
	authDecV10
	dst io.Writer

	buffer packageV10
	offset int
}

func (w *decWriterV1) Write(p []byte) (n int, err error) {
	if w.offset > 0 && w.offset < headerSize {
		remaining := headerSize - w.offset
		if len(p) < remaining {
			n = copy(w.buffer[w.offset:], p)
			w.offset += n
			return
		}
		n = copy(w.buffer[w.offset:], p[:remaining])
		p = p[remaining:]
		w.offset += n
	}
	if w.offset >= headerSize {
		remaining := w.buffer.Length() - w.offset
		if len(p) < remaining {
			nn := copy(w.buffer[w.offset:], p)
			w.offset += nn
			return n + nn, err
		}
		n += copy(w.buffer[w.offset:], p[:remaining])
		if err = w.Open(w.buffer.Payload(), w.buffer[:w.buffer.Length()]); err != nil {
			return n, err
		}
		if err = flush(w.dst, w.buffer.Payload()); err != nil {
			return n, err
		}
		p = p[remaining:]
		w.offset = 0
	}
	for len(p) > headerSize {
		packageLen := headerSize + tagSize + headerV10(p).Len()
		if len(p) < packageLen {
			w.offset = copy(w.buffer[:], p)
			n += w.offset
			return n, err
		}
		if err = w.Open(w.buffer[headerSize:packageLen-tagSize], p[:packageLen]); err != nil {
			return n, err
		}
		if err = flush(w.dst, w.buffer[headerSize:packageLen-tagSize]); err != nil {
			return n, err
		}
		p = p[packageLen:]
		n += packageLen
	}
	if len(p) > 0 {
		w.offset = copy(w.buffer[:], p)
		n += w.offset
	}
	return n, nil
}

func (w *decWriterV1) Close() error {
	if w.offset > 0 {
		if w.offset < headerSize {
			return errMissingHeader
		}
		header := headerV10(w.buffer[:headerSize])
		if w.offset < headerSize+header.Len()+tagSize {
			return errPayloadTooShort
		}
		if err := w.Open(w.buffer.Payload(), w.buffer[:w.buffer.Length()]); err != nil {
			return err
		}
		if err := flush(w.dst, w.buffer.Payload()); err != nil {
			return err
		}
	}
	if dst, ok := w.dst.(io.Closer); ok {
		return dst.Close()
	}
	return nil
}

type encWriterV1 struct {
	authEncV10
	dst io.Writer

	buffer      packageV10
	offset      int
	payloadSize int
}

func (w *encWriterV1) Write(p []byte) (n int, err error) {
	if w.offset > 0 {
		remaining := w.payloadSize - w.offset
		if len(p) < remaining {
			n = copy(w.buffer[headerSize+w.offset:], p)
			w.offset += n
			return
		}
		n = copy(w.buffer[headerSize+w.offset:], p[:remaining])
		w.Seal(w.buffer, w.buffer[headerSize:headerSize+w.payloadSize])
		if err = flush(w.dst, w.buffer[:w.buffer.Length()]); err != nil {
			return n, err
		}
		p = p[remaining:]
		w.offset = 0
	}
	for len(p) >= w.payloadSize {
		w.Seal(w.buffer[:], p[:w.payloadSize])
		if err = flush(w.dst, w.buffer[:w.buffer.Length()]); err != nil {
			return n, err
		}
		p = p[w.payloadSize:]
		n += w.payloadSize
	}
	if len(p) > 0 {
		w.offset = copy(w.buffer[headerSize:], p)
		n += w.offset
	}
	return
}

func (w *encWriterV1) Close() error {
	if w.offset > 0 {
		w.Seal(w.buffer[:], w.buffer[headerSize:headerSize+w.offset])
		if err := flush(w.dst, w.buffer[:w.buffer.Length()]); err != nil {
			return err
		}
	}
	if dst, ok := w.dst.(io.Closer); ok {
		return dst.Close()
	}
	return nil
}

func flush(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

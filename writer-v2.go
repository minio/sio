// Copyright (C) 2018 Minio Inc.
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

import (
	"io"
)

type encWriterV20 struct {
	authEncV20
	dst io.Writer

	buffer packageV20
	offset int
}

func encryptWriterV20(dst io.Writer, config *Config) (*encWriterV20, error) {
	ae, err := newAuthEncV20(config)
	if err != nil {
		return nil, err
	}
	return &encWriterV20{
		authEncV20: ae,
		dst:        dst,
		buffer:     make(packageV20, maxPackageSize),
	}, nil
}

func (w *encWriterV20) Write(p []byte) (n int, err error) {
	if w.finalized {
		panic("sio: write to stream after close")
	}
	if w.offset > 0 {
		remaining := maxPayloadSize - w.offset
		if len(p) <= remaining {
			w.offset += copy(w.buffer[headerSize+w.offset:], p)
			return len(p), nil
		}
		n = copy(w.buffer[headerSize+w.offset:], p[:remaining])
		w.Seal(w.buffer, w.buffer[headerSize:headerSize+maxPayloadSize])
		if err = flush(w.dst, w.buffer); err != nil {
			return n, err
		}
		p = p[remaining:]
		w.offset = 0
	}
	for len(p) > maxPayloadSize {
		w.Seal(w.buffer, p[:maxPayloadSize])
		if err = flush(w.dst, w.buffer); err != nil {
			return n, err
		}
		p = p[maxPayloadSize:]
		n += maxPayloadSize
	}
	if len(p) > 0 {
		w.offset = copy(w.buffer[headerSize:], p)
		n += w.offset
	}
	return n, nil
}

func (w *encWriterV20) Close() error {
	if w.offset > 0 {
		w.SealFinal(w.buffer, w.buffer[headerSize:headerSize+w.offset])
		if err := flush(w.dst, w.buffer[:headerSize+w.offset+tagSize]); err != nil {
			return err
		}
		w.offset = 0
	}
	if closer, ok := w.dst.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type decWriterV20 struct {
	authDecV20
	dst io.Writer

	buffer packageV20
	offset int
}

func decryptWriterV20(dst io.Writer, config *Config) (*decWriterV20, error) {
	ad, err := newAuthDecV20(config)
	if err != nil {
		return nil, err
	}
	return &decWriterV20{
		authDecV20: ad,
		dst:        dst,
		buffer:     make(packageV20, maxPackageSize),
	}, nil
}

func (w *decWriterV20) Write(p []byte) (n int, err error) {
	if w.offset > 0 {
		remaining := headerSize + maxPayloadSize + tagSize - w.offset
		if len(p) < remaining {
			w.offset += copy(w.buffer[w.offset:], p)
			return len(p), nil
		}
		n = copy(w.buffer[w.offset:], p[:remaining])
		if err = w.Open(w.buffer[headerSize:headerSize+maxPayloadSize], w.buffer); err != nil {
			return n, err
		}
		if err = flush(w.dst, w.buffer[headerSize:headerSize+maxPayloadSize]); err != nil {
			return n, err
		}
		p = p[remaining:]
		w.offset = 0
	}
	for len(p) >= maxPackageSize {
		if err = w.Open(w.buffer[headerSize:headerSize+maxPayloadSize], p[:maxPackageSize]); err != nil {
			return n, err
		}
		if err = flush(w.dst, w.buffer[headerSize:headerSize+maxPayloadSize]); err != nil {
			return n, err
		}
		p = p[maxPackageSize:]
		n += maxPackageSize
	}
	if len(p) > 0 {
		w.offset = copy(w.buffer[:], p)
		n += w.offset
	}
	return n, nil
}

func (w *decWriterV20) Close() error {
	if w.offset > 0 {
		if w.offset <= headerSize+tagSize {
			return errInvalidPayloadSize
		}
		if err := w.Open(w.buffer[headerSize:w.offset-tagSize], w.buffer[:w.offset]); err != nil {
			return err
		}
		if err := flush(w.dst, w.buffer[headerSize:w.offset-tagSize]); err != nil {
			return err
		}
		w.offset = 0
	}
	if closer, ok := w.dst.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

package main

import (
  "io"
  "crypto/cipher"
  "crypto/aes"
  "errors"
  "os"
)

type StreamDecrypter struct {
  Block cipher.Block
  Stream cipher.Stream
}

func NewStreamDecrypter(key []byte) *StreamDecrypter {
  c, err := aes.NewCipher(key)
  if err != nil {
    panic(err)
  }
  return &StreamDecrypter{
    Block: c,
    Stream: nil,
  }
}

func (sd *StreamDecrypter) Decrypt(f io.Reader) ([]byte, error) {
  res := []byte{}
  bs := sd.Block.BlockSize()
  iv := make([]byte, bs)
  if _, err := io.ReadFull(f, iv); err != nil {
    return res, err
  }
  
  sd.Stream = cipher.NewCFBDecrypter(sd.Block, iv)
  for {
    buf := make([]byte, bs)
    out := make([]byte, bs)
    _, err := io.ReadFull(f, buf)
    if err != nil {
      if errors.Is(err, io.EOF) {
        return res, nil
      }
      return res, err
    }
    sd.Stream.XORKeyStream(out, buf)
    res = append(res, out...)
  }
}

func usage(cmd string) {
  os.Stderr.WriteString("Usage: " + cmd + " [aes_key] < file_to_decrypt\n")
}

func main() {
  if len(os.Args) != 2 {
    usage(os.Args[0])
    return
  }
  key := []byte(os.Args[1])
  if len(key) != 8 || len(key) != 16 || len(key) != 24 || len(key) != 32 {
    os.Stderr.WriteString("Invalid key size\n")
    usage(os.Args[0])
    return
  }
  sd := NewStreamDecrypter(key)
  out, err := sd.Decrypt(os.Stdin)
  if err != nil {
    panic(err)
  }
  os.Stdout.Write(out)
}